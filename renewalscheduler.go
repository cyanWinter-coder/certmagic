// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RetryAfterError wraps an issuance/renewal failure with a time at which
// the server says the operation may be retried. Issuers (or wrappers around
// them) can return it to communicate a server-mandated wait, such as one
// derived from an HTTP Retry-After header. When a renewal fails with this
// error, the renewal backoff schedule waits until at least RetryAfter before
// attempting again, so the server's timing takes precedence over the local
// exponential backoff schedule.
type RetryAfterError struct {
	// RetryAfter is the earliest time at which the server allows another attempt.
	RetryAfter time.Time

	// Err is the underlying failure.
	Err error
}

// Error implements the error interface.
func (e RetryAfterError) Error() string {
	if e.Err == nil {
		return "server asked to retry after " + e.RetryAfter.Format(time.RFC3339)
	}
	return e.Err.Error()
}

// Unwrap exposes the underlying error to errors.Is/errors.As.
func (e RetryAfterError) Unwrap() error { return e.Err }

// retryAfterFrom extracts a server-mandated retry time from err, if the error
// chain contains a RetryAfterError.
func retryAfterFrom(err error) (time.Time, bool) {
	var rae RetryAfterError
	if errors.As(err, &rae) && !rae.RetryAfter.IsZero() {
		return rae.RetryAfter, true
	}
	return time.Time{}, false
}

// maxRenewalRetryWait caps how long a single backoff wait may be, even when
// the server asks for a longer Retry-After. It prevents a misbehaving or
// misparsed server value from parking a certificate's renewal indefinitely.
const maxRenewalRetryWait = 24 * time.Hour

// errRenewalSchedulerStopped is returned by Submit after the scheduler has
// been stopped.
var errRenewalSchedulerStopped = errors.New("renewal scheduler is stopped")

// renewalScheduler serializes and paces renewal jobs.
//
// It enforces two levels of concurrency limits:
//
//   - a global limit on jobs running at once, across every issuer; and
//   - a per-issuer limit (with optional per-issuer overrides).
//
// A limit of zero means unlimited, which is the default and preserves the
// historical behavior of running every submitted job immediately.
//
// Jobs are kept in FIFO submission order. A job whose issuer is at capacity
// stays in its queue position instead of being failed or re-enqueued, so a
// persistently failing issuer cannot make one of its domains jump ahead of
// other waiting domains, and cannot block other issuers: the dispatcher
// simply skips the saturated issuer and starts eligible jobs behind it.
//
// A job key identifies a logical renewal identity (e.g. "renew_"+domain).
// Submitting a key that is already queued or running is a no-op: duplicate
// renewals coalesce onto the existing job, which keeps its original position
// in the queue.
//
// Every queued job owns exactly one goroutine, which blocks until either the
// job is dispatched, its context is canceled, or the scheduler is stopped.
// Canceling a queued job's context removes it from the queue and releases
// everything it held without leaving any goroutine behind.
type renewalScheduler struct {
	mu sync.Mutex

	globalLimit int                     // <= 0 means unlimited
	issuerLimit int                     // <= 0 means unlimited
	overrides   map[string]int          // optional per-issuer limit overrides
	queued      []*renewalTask          // FIFO; tasks that have not started yet
	active      map[string]int          // issuerKey -> number of running jobs
	names       map[string]*renewalTask // every queued or running task, by key

	wake    chan struct{} // buffered(1); signals the dispatcher to re-evaluate
	stop    chan struct{} // closed once to shut down
	stopped bool

	dispatcherWg sync.WaitGroup // the single dispatcher goroutine
	taskWg       sync.WaitGroup // one per submitted task goroutine
}

// renewalTask is a single scheduled renewal.
type renewalTask struct {
	key       string
	issuerKey string
	ctx       context.Context
	logger    *zap.Logger
	run       func(context.Context) error

	// ready is closed by the dispatcher when the job may run.
	ready chan struct{}

	// started is set under the scheduler lock when the dispatcher acquires
	// quota and closes ready; finish() uses it to decide whether to release
	// an issuer slot.
	started bool
}

// newRenewalScheduler creates a scheduler and starts its dispatcher.
// globalLimit and issuerLimit of zero mean unlimited; overrides supplies
// optional per-issuer-key limits and may be nil.
func newRenewalScheduler(globalLimit, issuerLimit int, overrides map[string]int) *renewalScheduler {
	rs := &renewalScheduler{
		globalLimit: globalLimit,
		issuerLimit: issuerLimit,
		overrides:   overrides,
		active:      make(map[string]int),
		names:       make(map[string]*renewalTask),
		wake:        make(chan struct{}, 1),
		stop:        make(chan struct{}),
	}
	rs.dispatcherWg.Add(1)
	go rs.dispatchLoop()
	return rs
}

// Submit enqueues a renewal job identified by key. If a job with the same key
// is already queued or running, the submission is coalesced into it and this
// is a no-op without error. The job runs with the given ctx; canceling it
// while the job is still queued removes it from the queue and releases its
// quota reservation. run is invoked at most once, only after all applicable
// concurrency limits have capacity.
func (rs *renewalScheduler) Submit(ctx context.Context, logger *zap.Logger, key, issuerKey string, run func(context.Context) error) error {
	if key == "" {
		return errors.New("renewal job requires a non-empty key")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	t := &renewalTask{
		key:       key,
		issuerKey: issuerKey,
		ctx:       ctx,
		logger:    logger,
		run:       run,
		ready:     make(chan struct{}),
	}

	rs.mu.Lock()
	if rs.stopped {
		rs.mu.Unlock()
		return errRenewalSchedulerStopped
	}
	if _, exists := rs.names[key]; exists {
		// coalesce duplicate renewals of the same logical identity;
		// the existing job keeps its stable position in the queue
		rs.mu.Unlock()
		if logger != nil {
			logger.Debug("renewal already queued or in progress; coalescing duplicate request",
				zap.String("renewal_key", key))
		}
		return nil
	}
	rs.names[key] = t
	rs.queued = append(rs.queued, t)
	rs.mu.Unlock()

	rs.taskWg.Add(1)
	go rs.runTask(t)

	rs.signal()
	return nil
}

// Stop shuts the scheduler down. The dispatcher exits, and any jobs still
// queued are abandoned (their goroutines observe the stop signal, clean up
// their queue entries and quota, and exit). Jobs already running are not
// interrupted; Stop waits for every task goroutine to return, so no goroutine
// is leaked. It is safe to call more than once.
func (rs *renewalScheduler) Stop() {
	rs.mu.Lock()
	if rs.stopped {
		rs.mu.Unlock()
		return
	}
	rs.stopped = true
	close(rs.stop)
	rs.mu.Unlock()

	rs.dispatcherWg.Wait()
	rs.taskWg.Wait()
}

// dispatchLoop is the single goroutine that decides which queued jobs may
// start. Centralizing dispatch here makes the quota accounting and FIFO
// ordering decisions race-free without juggling per-issuer semaphores.
func (rs *renewalScheduler) dispatchLoop() {
	defer rs.dispatcherWg.Done()
	for {
		rs.mu.Lock()
		dispatchable := false
		for _, t := range rs.queued {
			if rs.canStartLocked(t) {
				dispatchable = true
				break
			}
		}
		rs.mu.Unlock()

		if dispatchable {
			// startEligible makes one FIFO pass; the next loop iteration
			// starts any further jobs that still fit within the limits.
			rs.startEligible()
			continue
		}

		// Nothing can start right now. Sleep until a job finishes, a new
		// job is submitted, or the scheduler is stopped. The wake channel
		// is buffered so a signal that arrived between the check above and
		// this select cannot be lost.
		select {
		case <-rs.wake:
			continue
		case <-rs.stop:
			return
		}
	}
}

// canStartLocked reports whether t is allowed to run now. Callers must hold
// rs.mu. A job whose context is already canceled is never started; its own
// goroutine is responsible for removing it via finish().
func (rs *renewalScheduler) canStartLocked(t *renewalTask) bool {
	select {
	case <-t.ctx.Done():
		return false
	default:
	}

	if rs.globalLimit > 0 {
		total := 0
		for _, n := range rs.active {
			total += n
		}
		if total >= rs.globalLimit {
			return false
		}
	}

	limit := rs.issuerLimit
	if override, ok := rs.overrides[t.issuerKey]; ok {
		limit = override
	}
	if limit > 0 && rs.active[t.issuerKey] >= limit {
		return false
	}

	return true
}

// startEligible makes one pass over the queue in FIFO order and starts every
// job whose limits currently have capacity. Saturated or canceled jobs remain
// in place at their original queue position.
func (rs *renewalScheduler) startEligible() {
	rs.mu.Lock()
	queued := rs.queued
	keep := queued[:0]
	for _, t := range queued {
		if rs.canStartLocked(t) {
			t.started = true
			rs.active[t.issuerKey]++
			close(t.ready)
		} else {
			keep = append(keep, t)
		}
	}
	// Nil out the now-unused tail of the shared backing array so dropped
	// task pointers can be garbage collected instead of being retained.
	for i := len(keep); i < len(queued); i++ {
		queued[i] = nil
	}
	rs.queued = keep
	rs.mu.Unlock()
}

// runTask is the per-job goroutine. It waits for one of three outcomes:
// dispatch (then it runs the job), context cancellation while still queued,
// or scheduler shutdown. In every case finish() reconciles the scheduler's
// bookkeeping, so no quota or goroutine is leaked.
func (rs *renewalScheduler) runTask(t *renewalTask) {
	defer rs.taskWg.Done()

	select {
	case <-t.ready:
		if err := t.run(t.ctx); err != nil && t.logger != nil {
			t.logger.Error("renewal job failed",
				zap.String("renewal_key", t.key),
				zap.String("issuer", t.issuerKey),
				zap.Error(err))
		}
	case <-t.ctx.Done():
		// Canceled while waiting for a slot: never ran, never held a slot.
		if t.logger != nil {
			t.logger.Debug("renewal job canceled before it started",
				zap.String("renewal_key", t.key))
		}
	case <-rs.stop:
		// Scheduler shut down while the job was queued.
	}

	rs.finish(t)
}

// finish removes t from whichever structure it occupies, releases its issuer
// slot if it had acquired one, and wakes the dispatcher so another job can
// take the freed capacity. It runs exactly once per task because each task
// goroutine exits after calling it.
func (rs *renewalScheduler) finish(t *renewalTask) {
	rs.mu.Lock()
	for i, q := range rs.queued {
		if q == t {
			queued := rs.queued
			rs.queued = append(queued[:i], queued[i+1:]...)
			// The append above shifts elements left but leaves the old
			// final slot holding a duplicate pointer; nil it so the task
			// can be garbage collected.
			queued[len(queued)-1] = nil
			break
		}
	}
	if t.started {
		if n := rs.active[t.issuerKey]; n > 1 {
			rs.active[t.issuerKey] = n - 1
		} else {
			delete(rs.active, t.issuerKey)
		}
	}
	delete(rs.names, t.key)
	rs.mu.Unlock()

	rs.signal()
}

// signal nudges the dispatcher to re-evaluate the queue. The send is
// non-blocking: if the dispatcher is not currently waiting, it is already
// either dispatching or about to re-evaluate, and the buffered channel holds
// at most one pending wake.
func (rs *renewalScheduler) signal() {
	select {
	case rs.wake <- struct{}{}:
	default:
	}
}

// queuedCount reports the number of jobs that have not started yet. It is
// intended for tests and diagnostics.
func (rs *renewalScheduler) queuedCount() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.queued)
}

// activeCount reports the number of currently running jobs, optionally
// restricted to a single issuer key (an empty key means all issuers). It is
// intended for tests and diagnostics.
func (rs *renewalScheduler) activeCount(issuerKey string) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if issuerKey != "" {
		return rs.active[issuerKey]
	}
	total := 0
	for _, n := range rs.active {
		total += n
	}
	return total
}
