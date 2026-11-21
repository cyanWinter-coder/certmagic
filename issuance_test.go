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
	"fmt"
	"io"
	stdlog "log"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestIssuanceKeyCanonicalizesDomainIdentity verifies that domain
// spellings equivalent under case-folding, trailing root-dot removal,
// and IDNA/punycode encoding all collapse to the same coordinator key.
// This is what lets equivalent requests share one work item.
func TestIssuanceKeyCanonicalizesDomainIdentity(t *testing.T) {
	cases := []struct {
		inputs []string
	}{
		{[]string{"example.com", "EXAMPLE.com", "Example.COM", "  example.com  "}},
		{[]string{"example.com.", "example.com", "EXAMPLE.COM."}},
		// Unicode IDN and its punycode form must identify the same domain.
		{[]string{"bücher.example", "xn--bcher-kva.example"}},
		// Wildcards are canonicalized label-by-label so the "*." survives.
		{[]string{"*.example.com", "*.EXAMPLE.com.", "*.Example.COM"}},
	}
	for i, tc := range cases {
		keys := make(map[string]struct{})
		for _, in := range tc.inputs {
			keys[issuanceKey(in)] = struct{}{}
		}
		if len(keys) != 1 {
			t.Errorf("case %d: expected all equivalent names to share one key, got %d distinct keys for %v",
				i, len(keys), tc.inputs)
		}
	}

	// Distinct domains must remain distinct, and malformed/non-domain
	// identifiers fall back to trimmed/lower-cased/dot-stripped form
	// rather than collapsing into unrelated names.
	distinct := []string{"a.example.com", "b.example.com", "127.0.0.1", "::1"}
	seen := make(map[string]struct{})
	for _, d := range distinct {
		k := issuanceKey(d)
		if _, dup := seen[k]; dup {
			t.Errorf("distinct identifier %q collapsed onto an existing key %q", d, k)
		}
		seen[k] = struct{}{}
	}

	if got := issuanceKey("  "); got != "" {
		t.Errorf("expected blank name to canonicalize to empty string, got %q", got)
	}
}

// TestIssuanceQueueCoalescesEquivalentRequests verifies that concurrent
// requests carrying equivalent spellings of one domain run the issuance
// function exactly once and all receive its result.
func TestIssuanceQueueCoalescesEquivalentRequests(t *testing.T) {
	q := newIssuanceQueue()
	logger := zap.NewNop()

	var runs atomic.Int32
	release := make(chan struct{})

	names := []string{"slow.example.com", "SLOW.Example.COM", "slow.example.com."}
	works := make([]*issuanceWork, len(names))
	for i, n := range names {
		n := n
		works[i] = q.submit(logger, issuanceKey(n), func(ctx context.Context) (any, error) {
			runs.Add(1)
			<-release
			return nil, nil
		})
	}

	// All three must have joined the same work item.
	for i := 1; i < len(works); i++ {
		if works[i] != works[0] {
			t.Fatalf("request %d did not coalesce onto the shared work item", i)
		}
	}
	if !q.has(issuanceKey(names[0])) {
		t.Fatal("coordinator should report the work item as in flight")
	}

	// A number of additional waiters attach while the single run is blocked.
	const extraWaiters = 8
	var wg sync.WaitGroup
	errs := make(chan error, extraWaiters)
	for i := 0; i < extraWaiters; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- works[0].wait(context.Background())
		}()
	}

	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("waiter expected nil result, got: %v", err)
		}
	}

	if got := runs.Load(); got != 1 {
		t.Errorf("expected issuance to run exactly once, got %d runs", got)
	}
	if !waitUntil(time.Second, func() bool { return !q.has(issuanceKey(names[0])) }) {
		t.Fatal("work item was not released from the coordinator after completion")
	}
}

// TestIssuanceQueueWaiterCancellationDoesNotStopSharedWork is the core
// cancellation-isolation guarantee: any single waiter giving up (its
// context canceled) must detach only that waiter, while the shared
// issuance runs to completion and remaining waiters still get the result.
func TestIssuanceQueueWaiterCancellationDoesNotStopSharedWork(t *testing.T) {
	q := newIssuanceQueue()
	logger := zap.NewNop()
	const key = "cancel.example.com"

	release := make(chan struct{})
	var completed atomic.Bool
	work := q.submit(logger, key, func(ctx context.Context) (any, error) {
		<-release
		// If a waiter's cancellation propagated into the run context,
		// this would return early and the "completed" marker below would
		// never be set.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("run context was canceled by a waiter: %w", ctx.Err())
		}
		completed.Store(true)
		return nil, nil
	})

	// Two waiters: one cancels almost immediately, the other sticks around.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelErr := make(chan error, 1)
	go func() { cancelErr <- work.wait(cancelCtx) }()

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	select {
	case err := <-cancelErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter expected context.Canceled, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled waiter did not return")
	}

	// The shared work must still be in flight and must run to completion.
	if !q.has(key) {
		t.Fatal("shared work item disappeared when one waiter canceled")
	}

	// A waiter that joins after the cancellation observes the same item.
	later := q.submit(logger, key, func(ctx context.Context) (any, error) {
		t.Fatal("a second, duplicate issuance function must never run")
		return nil, nil
	})
	if later != work {
		t.Fatal("post-cancellation submit did not join the existing work item")
	}

	close(release)

	if err := work.wait(context.Background()); err != nil {
		t.Fatalf("remaining waiter expected success, got: %v", err)
	}
	if err := later.wait(context.Background()); err != nil {
		t.Fatalf("late-joining waiter expected success, got: %v", err)
	}
	if !completed.Load() {
		t.Fatal("shared issuance did not run to completion after a waiter canceled")
	}
	if !waitUntil(time.Second, func() bool { return !q.has(key) }) {
		t.Fatal("work item leaked after completion")
	}
}

// TestIssuanceQueueAllWaitersShareTerminalState verifies that every
// waiter observes the same terminal error from the single run, and that
// after the failure is terminal the item is removed so the next explicit
// request starts a fresh attempt (no permanent failure poisoning).
func TestIssuanceQueueAllWaitersShareTerminalState(t *testing.T) {
	q := newIssuanceQueue()
	logger := zap.NewNop()
	const key = "failing.example.com"

	wantErr := errors.New("acme server rejected the request")
	var firstRuns atomic.Int32
	work := q.submit(logger, key, func(ctx context.Context) (any, error) {
		firstRuns.Add(1)
		return nil, wantErr
	})

	const waiters = 6
	var wg sync.WaitGroup
	errs := make([]error, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = work.wait(context.Background())
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, wantErr) {
			t.Errorf("waiter %d expected shared terminal error %v, got: %v", i, wantErr, err)
		}
	}
	if !waitUntil(time.Second, func() bool { return !q.has(key) }) {
		t.Fatal("failed work item was not released; future requests would be poisoned")
	}

	// The next explicit request must create a brand-new work item that
	// can succeed -- a prior failure is not a sticky terminal state.
	var secondRuns atomic.Int32
	retry := q.submit(logger, key, func(ctx context.Context) (any, error) {
		secondRuns.Add(1)
		return nil, nil
	})
	if retry == work {
		t.Fatal("retry joined the old, failed work item instead of starting fresh")
	}
	if err := retry.wait(context.Background()); err != nil {
		t.Fatalf("retry attempt expected success, got: %v", err)
	}
	if firstRuns.Load() != 1 || secondRuns.Load() != 1 {
		t.Fatalf("expected one failed attempt then one retry attempt, got first=%d second=%d",
			firstRuns.Load(), secondRuns.Load())
	}
}

// TestIssuanceQueueWaiterTimeoutIsLocal verifies that a waiter's
// deadline firing returns DeadlineExceeded to just that waiter while the
// work continues and another patient waiter still receives the result.
func TestIssuanceQueueWaiterTimeoutIsLocal(t *testing.T) {
	q := newIssuanceQueue()
	logger := zap.NewNop()
	const key = "slow-deadline.example.com"

	release := make(chan struct{})
	work := q.submit(logger, key, func(ctx context.Context) (any, error) {
		<-release
		return nil, nil
	})

	shortCtx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := work.wait(shortCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out waiter expected DeadlineExceeded, got: %v", err)
	}

	if !q.has(key) {
		t.Fatal("work item vanished after one waiter timed out")
	}

	done := make(chan error, 1)
	go func() { done <- work.wait(context.Background()) }()

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("patient waiter expected success, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("patient waiter never unblocked after work completed")
	}
}

// TestIssuanceQueueBoundedFIFOScheduling verifies requirement 4: with a
// bounded worker pool, distinct domains are admitted in submission order
// and a single slow domain cannot occupy more than its one worker, so
// other domains still get their finite concurrency opportunity.
func TestIssuanceQueueBoundedFIFOScheduling(t *testing.T) {
	q := newIssuanceQueue()
	q.maxConcurrent = 2
	logger := zap.NewNop()

	// Gate every run until the test releases them, so we can observe the
	// set of concurrently admitted work items.
	enter := make(chan string, 16)
	release := make(chan struct{})
	run := func(name string) func(context.Context) (any, error) {
		return func(ctx context.Context) (any, error) {
			enter <- name
			<-release
			return nil, nil
		}
	}

	// First domain is submitted twice: the second submission coalesces,
	// so it can never consume a second worker slot.
	w1 := q.submit(logger, "dom-a", run("dom-a"))
	w1Dup := q.submit(logger, "dom-a", run("dom-a-dup-must-not-run"))
	if w1Dup != w1 {
		t.Fatal("duplicate submission for an in-flight domain did not coalesce")
	}

	// Three more distinct domains queue behind dom-a.
	domains := []string{"dom-b", "dom-c", "dom-d"}
	for _, d := range domains {
		q.submit(logger, d, run(d))
	}

	// With maxConcurrent=2, the first two distinct domains in submission
	// order (dom-a, dom-b) must be admitted before dom-c or dom-d.
	started := make([]string, 0, 2)
	deadline := time.After(time.Second)
	for len(started) < 2 {
		select {
		case n := <-enter:
			started = append(started, n)
		case <-deadline:
			t.Fatalf("only %d workers started within the deadline: %v", len(started), started)
		}
	}
	sort.Strings(started)
	if started[0] != "dom-a" || started[1] != "dom-b" {
		t.Fatalf("expected FIFO admission of dom-a then dom-b, got %v", started)
	}

	// No third worker may be admitted while the first two are blocked,
	// proving the concurrency bound is enforced.
	select {
	case n := <-enter:
		t.Fatalf("concurrency bound violated: %q started while 2 workers were active", n)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	// Everything queued must eventually finish and release its slot.
	for _, d := range append([]string{"dom-a"}, domains...) {
		if !waitUntil(time.Second, func() bool { return !q.has(d) }) {
			t.Fatalf("work item for %s leaked after completion", d)
		}
	}
	if !waitUntil(time.Second, func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.activeWorkers == 0 && len(q.queue) == 0
	}) {
		t.Fatal("coordinator retained workers, queue entries, or in-flight references")
	}
}

// TestIssuanceQueueReleasesResourcesOnPanic verifies that a panicking
// issuance does not strand its work item, worker slot, or waiters: the
// panic is recovered into an error, waiters are unblocked, and a later
// request for the same domain can run again.
func TestIssuanceQueueReleasesResourcesOnPanic(t *testing.T) {
	// Swallow the coordinator's own panic log line; the panic is intentional.
	stdlog.SetOutput(io.Discard)
	t.Cleanup(func() { stdlog.SetOutput(io.Discard) })

	q := newIssuanceQueue()
	logger := zap.NewNop()
	const key = "panicky.example.com"

	var waiters sync.WaitGroup
	work := q.submit(logger, key, func(ctx context.Context) (any, error) {
		panic("simulated ACME panic")
	})
	for i := 0; i < 4; i++ {
		waiters.Add(1)
		go func() {
			defer waiters.Done()
			_ = work.wait(context.Background())
		}()
	}
	waiters.Wait()

	if work.err == nil {
		t.Fatal("expected a recovered panic to surface as a non-nil work error")
	}
	if !waitUntil(time.Second, func() bool { return !q.has(key) }) {
		t.Fatal("panicking work item was never released from the coordinator")
	}
	if !waitUntil(time.Second, func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.activeWorkers == 0
	}) {
		t.Fatal("worker slot leaked after a recovered panic")
	}

	// A subsequent, healthy request must run normally.
	var ran atomic.Bool
	next := q.submit(logger, key, func(ctx context.Context) (any, error) {
		ran.Store(true)
		return nil, nil
	})
	if err := next.wait(context.Background()); err != nil {
		t.Fatalf("request after panic expected success, got: %v", err)
	}
	if !ran.Load() {
		t.Fatal("post-panic request never executed")
	}
}

// TestIssuanceQueueNoGoroutineLeak is a coarse lifecycle check: after a
// burst of mixed success/failure/cancel/panic work, the coordinator must
// converge to zero active workers with no queued or in-flight items.
func TestIssuanceQueueNoGoroutineLeak(t *testing.T) {
	// Several jobs panic by design; keep their recovered stack traces
	// out of test output.
	stdlog.SetOutput(io.Discard)
	t.Cleanup(func() { stdlog.SetOutput(io.Discard) })

	q := newIssuanceQueue()
	q.maxConcurrent = 4
	logger := zap.NewNop()

	before := runtime.NumGoroutine()

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("burst-%d.example.com", i%12) // some deliberate coalescing
			ctx, cancel := context.WithCancel(context.Background())
			work := q.submit(logger, key, func(ctx context.Context) (any, error) {
				if i%7 == 0 {
					panic("burst panic")
				}
				if i%5 == 0 {
					return nil, errors.New("burst failure")
				}
				return nil, nil
			})
			// Every third caller cancels its own waiter immediately.
			if i%3 == 0 {
				cancel()
				_ = work.wait(ctx)
				return
			}
			defer cancel()
			_ = work.wait(context.Background())
		}(i)
	}
	wg.Wait()

	if !waitUntil(2*time.Second, func() bool {
		q.mu.Lock()
		defer q.mu.Unlock()
		return q.activeWorkers == 0 && len(q.queue) == 0 &&
			len(q.inflight) == 0
	}) {
		q.mu.Lock()
		t.Fatalf("coordinator did not settle: workers=%d queue=%d inflight=%d",
			q.activeWorkers, len(q.queue), len(q.inflight))
		q.mu.Unlock()
	}

	// Give ephemeral goroutine teardown a moment, then ensure the count
	// did not grow proportionally with the 40 requests.
	if !waitUntil(time.Second, func() bool { return runtime.NumGoroutine() <= before+2 }) {
		t.Errorf("goroutine count grew from %d to %d after the burst",
			before, runtime.NumGoroutine())
	}
}
