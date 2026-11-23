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
	"fmt"
	"runtime"
	"sync"
	"time"

	"go.uber.org/zap"
)

// This file implements the layered maintenance scheduler used by the
// background certificate maintenance loop (see maintain.go). It exists to
// give operators deterministic commit boundaries for renewal and OCSP
// maintenance:
//
//  1. Tasks are partitioned by issuer, and each partition has its own
//     concurrency quota, so one issuer's persistently failing (or slowly
//     hanging) tasks cannot occupy the whole queue and starve the
//     certificates of other issuers.
//  2. Renewal and OCSP tasks are separate layers: each computes its
//     scheduling priority from its own domain input (certificate expiry
//     vs. staple NextUpdate), and duplicate tasks for the same identity
//     are merged into one.
//  3. Tasks may carry a not-before time so backoff (including
//     server-requested waits, capped) is a scheduling property rather
//     than a sleep inside a worker; a task's partition quota is released
//     exactly once when it finishes, even if it is cancelled or panics.
//  4. Stopping the scheduler immediately stops accepting new tasks and
//     drops queued-but-unstarted ones, while started tasks are given a
//     bounded grace period to converge before their context is cancelled.

// maintenanceTaskKind identifies which layer of maintenance a task
// belongs to. Renewal and OCSP tasks compute priority separately and,
// at equal deadlines, renewals are scheduled first (the zero value
// sorts first in taskLess).
type maintenanceTaskKind int

const (
	taskKindRenewal maintenanceTaskKind = iota
	taskKindOCSP
)

func (k maintenanceTaskKind) String() string {
	switch k {
	case taskKindRenewal:
		return "renewal"
	case taskKindOCSP:
		return "ocsp"
	}
	return fmt.Sprintf("unknown(%d)", int(k))
}

// maintenanceTask is a single unit of maintenance work.
type maintenanceTask struct {
	// kind selects the maintenance layer (renewal or OCSP); it affects
	// scheduling order and how the task is executed.
	kind maintenanceTaskKind

	// issuer is the partition key (typically Issuer.IssuerKey). Tasks in
	// different partitions never contend for the same concurrency quota.
	issuer string

	// identity deduplicates tasks: submitting a task whose identity
	// matches an already-queued task merges the two instead of running
	// the work twice. Renewal tasks conventionally use "renew_"+name so
	// that de-duplication with renewal jobs submitted through the job
	// manager from other code paths keeps working. Empty disables
	// de-duplication.
	identity string

	// deadline is the scheduling priority: earlier deadlines run first.
	// Compute it with renewalPriority or ocspPriority.
	deadline time.Time

	// notBefore, if set, defers the task until the given time (backoff).
	notBefore time.Time

	// logger is used for task-level error reporting; may be nil.
	logger *zap.Logger

	// run performs the work. The passed context is cancelled if the
	// scheduler's shutdown grace period elapses; tasks should honor it.
	run func(ctx context.Context) error
}

// renewalPriority computes the scheduling deadline for a certificate
// renewal task: the certificate's expiration time. Certificates closer
// to expiry are scheduled ahead of longer-lived ones.
func renewalPriority(expires time.Time) time.Time { return expires }

// ocspPriority computes the scheduling deadline for an OCSP staple
// refresh task: the current staple's NextUpdate time. Staples closer to
// (or past) their NextUpdate are more urgent; a certificate with no
// staple at all (zero time) sorts ahead of everything else.
func ocspPriority(nextUpdate time.Time) time.Time { return nextUpdate }

// maintenanceTaskHandle lets a submitter wait for a task to settle:
// it is closed exactly once, when the task completes, is merged into a
// task that later completes, or is dropped without running (e.g. at
// shutdown). Waiters therefore never hang on a task that will never run.
type maintenanceTaskHandle struct {
	done chan struct{}
}

// wait blocks until the task settles or ctx is cancelled.
func (h maintenanceTaskHandle) wait(ctx context.Context) {
	select {
	case <-h.done:
	case <-ctx.Done():
	}
}

// queuedMaintenanceTask is a task plus the handles waiting on it. A
// merged duplicate appends its handle here so it settles together with
// the task it merged into.
type queuedMaintenanceTask struct {
	maintenanceTask
	handles []chan struct{}
}

// taskLess reports whether a should be scheduled before b: earliest
// deadline first, renewals before OCSP updates at equal deadlines, then
// by identity for determinism.
func taskLess(a, b *queuedMaintenanceTask) bool {
	if !a.deadline.Equal(b.deadline) {
		return a.deadline.Before(b.deadline)
	}
	if a.kind != b.kind {
		return a.kind < b.kind
	}
	return a.identity < b.identity
}

// schedPartition holds the scheduling state for one issuer.
type schedPartition struct {
	queue       []*queuedMaintenanceTask
	pending     map[string]*queuedMaintenanceTask // identity -> queued task
	running     int                               // tasks currently holding quota
	dispatching bool                              // whether a dispatch loop is alive
	wake        chan struct{}                     // buffered(1); signals state changes
}

// maintenanceScheduler is the layered, issuer-partitioned scheduler for
// certificate maintenance tasks. The zero value is not valid; use
// newMaintenanceScheduler.
type maintenanceScheduler struct {
	maxConcurrentPerPartition int
	logger                    *zap.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.Mutex
	partitions map[string]*schedPartition
	stopping   bool
	wg         sync.WaitGroup // counts started-but-unfinished tasks
}

// newMaintenanceScheduler returns a scheduler that allows up to
// maxConcurrentPerPartition tasks of the same issuer to run at once.
func newMaintenanceScheduler(maxConcurrentPerPartition int, logger *zap.Logger) *maintenanceScheduler {
	if maxConcurrentPerPartition <= 0 {
		maxConcurrentPerPartition = 1
	}
	if logger == nil {
		logger = zap.NewNop()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &maintenanceScheduler{
		maxConcurrentPerPartition: maxConcurrentPerPartition,
		logger:                    logger,
		ctx:                       ctx,
		cancel:                    cancel,
		partitions:                make(map[string]*schedPartition),
	}
}

// submit queues t for execution and returns a handle that settles when
// the task does. If the scheduler is stopping, the task is rejected and
// the returned handle is already settled. If a task with the same
// non-empty identity is already queued, the two are merged: the queued
// task keeps its run function but adopts the earlier deadline and
// not-before time, and the returned handle settles when it does.
func (s *maintenanceScheduler) submit(t maintenanceTask) maintenanceTaskHandle {
	h := maintenanceTaskHandle{done: make(chan struct{})}
	if t.logger == nil {
		t.logger = s.logger
	}

	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		close(h.done)
		return h
	}
	p, ok := s.partitions[t.issuer]
	if !ok {
		p = &schedPartition{
			pending: make(map[string]*queuedMaintenanceTask),
			wake:    make(chan struct{}, 1),
		}
		s.partitions[t.issuer] = p
	}
	if t.identity != "" {
		if existing, ok := p.pending[t.identity]; ok {
			// merge: one execution, earliest scheduling parameters win
			if t.deadline.Before(existing.deadline) {
				existing.deadline = t.deadline
			}
			if t.notBefore.Before(existing.notBefore) {
				existing.notBefore = t.notBefore
			}
			existing.handles = append(existing.handles, h.done)
			s.mu.Unlock()
			s.signal(p)
			return h
		}
	}
	qt := &queuedMaintenanceTask{maintenanceTask: t, handles: []chan struct{}{h.done}}
	if t.identity != "" {
		p.pending[t.identity] = qt
	}
	p.queue = append(p.queue, qt)
	if !p.dispatching {
		p.dispatching = true
		go s.dispatchLoop(p)
	}
	s.mu.Unlock()

	s.signal(p)
	return h
}

// stop makes the scheduler stop accepting new tasks, drops tasks that
// were queued but never started (settling their handles), and waits up
// to grace for started tasks to finish. If any are still running after
// grace, their context is cancelled and they get one more grace period
// to unwind before stop returns regardless. It is idempotent.
func (s *maintenanceScheduler) stop(grace time.Duration) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return
	}
	s.stopping = true
	for _, p := range s.partitions {
		// queued tasks never started, so they hold no quota; settle
		// their handles so waiters don't block forever
		for _, qt := range p.queue {
			for _, done := range qt.handles {
				close(done)
			}
		}
		p.queue = nil
		p.pending = make(map[string]*queuedMaintenanceTask)
		s.signal(p)
	}
	s.mu.Unlock()

	// started tasks converge within the grace period
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(grace)
	select {
	case <-done:
		timer.Stop()
		return
	case <-timer.C:
	}

	// deadline exceeded: cancel task contexts so tasks that honor
	// cancellation can unwind, then bound that unwinding as well
	s.cancel()
	timer.Reset(grace)
	select {
	case <-done:
	case <-timer.C:
	}
	timer.Stop()
}

// signal wakes the partition's dispatch loop, if one is listening.
func (s *maintenanceScheduler) signal(p *schedPartition) {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// dispatchLoop dispatches a partition's tasks in priority order as
// quota becomes available. It exits whenever the queue drains, and is
// restarted by the next submit, so idle partitions hold no goroutines.
func (s *maintenanceScheduler) dispatchLoop(p *schedPartition) {
	for {
		s.mu.Lock()
		if len(p.queue) == 0 {
			p.dispatching = false
			s.mu.Unlock()
			return
		}

		var timer *time.Timer
		var timerC <-chan time.Time
		if p.running < s.maxConcurrentPerPartition {
			now := time.Now()
			for p.running < s.maxConcurrentPerPartition {
				idx := indexOfNextDueTask(p.queue, now)
				if idx < 0 {
					break
				}
				qt := p.queue[idx]
				p.queue = append(p.queue[:idx], p.queue[idx+1:]...)
				if qt.identity != "" {
					delete(p.pending, qt.identity)
				}
				p.running++
				s.wg.Add(1)
				go s.runTask(p, qt)
			}
			// any remaining tasks are waiting for their not-before time;
			// arm a timer for the earliest one
			if len(p.queue) > 0 {
				earliest := p.queue[0].notBefore
				for _, qt := range p.queue[1:] {
					if qt.notBefore.Before(earliest) {
						earliest = qt.notBefore
					}
				}
				wait := time.Until(earliest)
				if wait < 0 {
					wait = 0
				}
				timer = time.NewTimer(wait)
				timerC = timer.C
			}
		}
		s.mu.Unlock()

		// sleep until woken by a submit or task completion, or until the
		// next not-before time arrives; if quota is exhausted there is no
		// timer and only a completion (which signals) can make progress
		select {
		case <-p.wake:
		case <-timerC:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

// indexOfNextDueTask returns the index of the highest-priority queued
// task whose not-before time has arrived, or -1 if there is none.
func indexOfNextDueTask(queue []*queuedMaintenanceTask, now time.Time) int {
	idx := -1
	for i, qt := range queue {
		if qt.notBefore.After(now) {
			continue
		}
		if idx < 0 || taskLess(qt, queue[idx]) {
			idx = i
		}
	}
	return idx
}

// runTask executes one dispatched task. Renewal tasks are executed
// through the package-level job manager so that name-based
// de-duplication with renewal jobs submitted from other code paths
// (e.g. ManageAsync) keeps working exactly as before; other tasks run
// on their own goroutine.
func (s *maintenanceScheduler) runTask(p *schedPartition, qt *queuedMaintenanceTask) {
	if qt.kind == taskKindRenewal {
		job := func() error {
			defer s.finishTask(p, qt)
			return s.runSafely(qt)
		}
		if !jm.Submit(qt.logger, qt.identity, job) {
			// a job with this name is already in flight elsewhere;
			// treat this task as merged into it and settle now
			s.finishTask(p, qt)
		}
		return
	}
	defer s.finishTask(p, qt)
	if err := s.runSafely(qt); err != nil {
		qt.logger.Error("maintenance task failed",
			zap.String("kind", qt.kind.String()),
			zap.String("issuer", qt.issuer),
			zap.String("identity", qt.identity),
			zap.Error(err))
	}
}

// finishTask releases the task's partition quota and settles its
// handles. It runs exactly once per dispatched task, including when the
// task is cancelled or panics, so a cancelled task never leaks quota.
func (s *maintenanceScheduler) finishTask(p *schedPartition, qt *queuedMaintenanceTask) {
	for _, done := range qt.handles {
		close(done)
	}
	s.mu.Lock()
	p.running--
	s.mu.Unlock()
	s.wg.Done()
	s.signal(p)
}

// runSafely runs the task, converting a panic into an error so a
// misbehaving task cannot kill a scheduler or job-manager goroutine.
func (s *maintenanceScheduler) runSafely(qt *queuedMaintenanceTask) (err error) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, stackTraceBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			qt.logger.Error("panic in maintenance task",
				zap.String("kind", qt.kind.String()),
				zap.String("issuer", qt.issuer),
				zap.String("identity", qt.identity),
				zap.Any("error", r),
				zap.ByteString("stack", buf))
			err = fmt.Errorf("panic in %s maintenance task %s: %v", qt.kind, qt.identity, r)
		}
	}()
	return qt.run(s.ctx)
}

const (
	// defaultMaxMaintenanceTasksPerIssuer is the default per-issuer
	// concurrency quota for maintenance tasks. It bounds how many
	// renewals/OCSP refreshes of one issuer may run at once, so a
	// struggling issuer cannot occupy the whole maintenance pipeline.
	defaultMaxMaintenanceTasksPerIssuer = 4

	// maintenanceShutdownGrace is how long Cache.Stop waits for started
	// maintenance tasks to converge before cancelling their contexts
	// (and, at most, once more for the cancellation to take effect).
	maintenanceShutdownGrace = 30 * time.Second
)

// maintenanceScheduler returns the cache's maintenance scheduler,
// creating it on first use.
func (certCache *Cache) maintenanceScheduler() *maintenanceScheduler {
	certCache.schedMu.Lock()
	defer certCache.schedMu.Unlock()
	if certCache.sched == nil {
		certCache.sched = newMaintenanceScheduler(defaultMaxMaintenanceTasksPerIssuer, certCache.logger)
	}
	return certCache.sched
}

// stopMaintenanceScheduler stops the cache's maintenance scheduler, if
// one was created, waiting up to grace for started tasks to converge.
func (certCache *Cache) stopMaintenanceScheduler(grace time.Duration) {
	certCache.schedMu.Lock()
	sched := certCache.sched
	certCache.schedMu.Unlock()
	if sched != nil {
		sched.stop(grace)
	}
}
