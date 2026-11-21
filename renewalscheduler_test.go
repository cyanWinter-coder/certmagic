package certmagic

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// jobGate lets a test block a scheduled job until the test releases it,
// providing deterministic control over "in-flight" jobs without sleeping.
type jobGate struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func newJobGate() *jobGate {
	return &jobGate{
		release: make(chan struct{}),
		started: make(chan struct{}),
	}
}

func (g *jobGate) job() func(context.Context) error {
	return func(ctx context.Context) error {
		g.once.Do(func() { close(g.started) })
		select {
		case <-g.release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (g *jobGate) waitStarted() {
	select {
	case <-g.started:
	case <-time.After(2 * time.Second):
		panic("job never started")
	}
}

func (g *jobGate) allow() { close(g.release) }

// assertGoroutinesSettled polls until no test-scheduler goroutines remain.
// runtime goroutine stacks include the function name, so we count stacks
// mentioning renewalScheduler methods rather than comparing raw totals,
// which would be flaky under the race detector and other test machinery.
func assertGoroutinesSettled(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		stacks := string(buf[:n])
		// runTask is the per-job goroutine; dispatchLoop the scheduler one.
		if !contains(stacks, "renewalScheduler.runTask") &&
			!contains(stacks, "renewalScheduler.dispatchLoop") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("renewal scheduler goroutines were still running after they should have exited")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestRenewalSchedulerDefaultRunsEverythingImmediately verifies the default
// configuration (both limits zero = unlimited) preserves the historical
// behavior: every submitted job starts without waiting, even when many are
// submitted in a burst.
func TestRenewalSchedulerDefaultRunsEverythingImmediately(t *testing.T) {
	rs := newRenewalScheduler(0, 0, nil)
	t.Cleanup(rs.Stop)

	const n = 25
	var ran atomic.Int32
	for i := range n {
		key := fmt.Sprintf("renew_default_%d", i)
		if err := rs.Submit(context.Background(), zap.NewNop(), key, "issuer_a", func(context.Context) error {
			ran.Add(1)
			return nil
		}); err != nil {
			t.Fatalf("Submit %s: %v", key, err)
		}
	}
	if !waitUntil(2*time.Second, func() bool { return ran.Load() == n }) {
		t.Fatalf("expected all %d unlimited jobs to run, got %d", n, ran.Load())
	}
	if !waitUntil(time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatal("expected queue and active set to drain to zero")
	}
}

// TestRenewalSchedulerGlobalLimitEnforced is the restart-burst case: many
// domains come due at once after a restart, and the global concurrency limit
// must hold the number of simultaneous renewals at or below the configured
// ceiling, while jobs that finish free capacity for the rest.
func TestRenewalSchedulerGlobalLimitEnforced(t *testing.T) {
	const limit = 2
	rs := newRenewalScheduler(limit, 0, nil)
	t.Cleanup(rs.Stop)

	const n = 6
	gates := make([]*jobGate, n)
	var concurrent atomic.Int32
	var maxObserved atomic.Int32

	for i := range n {
		gates[i] = newJobGate()
		gate := gates[i]
		key := fmt.Sprintf("renew_global_%d", i)
		err := rs.Submit(context.Background(), zap.NewNop(), key, "issuer_a", func(ctx context.Context) error {
			cur := concurrent.Add(1)
			for {
				peak := maxObserved.Load()
				if cur <= peak || maxObserved.CompareAndSwap(peak, cur) {
					break
				}
			}
			defer concurrent.Add(-1)
			return gate.job()(ctx)
		})
		if err != nil {
			t.Fatalf("Submit %s: %v", key, err)
		}
	}

	// Only `limit` jobs may be running while the rest wait.
	if !waitUntil(2*time.Second, func() bool {
		return rs.activeCount("") == limit && rs.queuedCount() == n-limit
	}) {
		t.Fatalf("expected %d active and %d queued under global limit, got active=%d queued=%d",
			limit, n-limit, rs.activeCount(""), rs.queuedCount())
	}
	// Give the dispatcher a little room to prove it never overshoots.
	time.Sleep(50 * time.Millisecond)
	if got := rs.activeCount(""); got != limit {
		t.Fatalf("global limit overshot: active=%d want %d", got, limit)
	}
	if got := maxObserved.Load(); got > limit {
		t.Fatalf("observed %d simultaneous jobs, global limit is %d", got, limit)
	}

	// Releasing one job must admit exactly one replacement.
	gates[0].allow()
	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == n-limit-1 }) {
		t.Fatalf("expected one queued job to be admitted after a slot freed, got queued=%d", rs.queuedCount())
	}
	if got := rs.activeCount(""); got != limit {
		t.Fatalf("expected active count to refill to %d, got %d", limit, got)
	}

	// Release everything; the whole burst must drain without exceeding the
	// ceiling at any point.
	for i := 1; i < n; i++ {
		gates[i].allow()
	}
	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatalf("scheduler did not drain: active=%d queued=%d", rs.activeCount(""), rs.queuedCount())
	}
	if got := maxObserved.Load(); got > limit {
		t.Fatalf("peak concurrency %d exceeded global limit %d", got, limit)
	}
}

// TestRenewalSchedulerPerIssuerLimitIsolatesFailures proves requirement #2:
// one issuer being saturated (e.g. persistently failing and holding its
// slots in long retries) cannot block a different issuer. The healthy
// issuer keeps getting slots even while the unhealthy one is at capacity.
func TestRenewalSchedulerPerIssuerLimitIsolatesFailures(t *testing.T) {
	rs := newRenewalScheduler(0, 1, nil) // one job per issuer, global unlimited
	t.Cleanup(rs.Stop)

	blockedA1, blockedA2 := newJobGate(), newJobGate()
	healthyB := newJobGate()

	mustSubmit := func(key, issuer string, gate *jobGate) {
		t.Helper()
		if err := rs.Submit(context.Background(), zap.NewNop(), key, issuer, gate.job()); err != nil {
			t.Fatalf("Submit %s: %v", key, err)
		}
	}

	// Issuer A fills its single slot and queues behind itself.
	mustSubmit("renew_a1", "issuer_a", blockedA1)
	blockedA1.waitStarted()
	mustSubmit("renew_a2", "issuer_a", blockedA2)

	if !waitUntil(time.Second, func() bool {
		return rs.activeCount("issuer_a") == 1 && rs.queuedCount() == 1
	}) {
		t.Fatalf("expected issuer A at 1 active / 1 queued, got active=%d queued=%d",
			rs.activeCount("issuer_a"), rs.queuedCount())
	}

	// A job for a different issuer must start immediately despite A being
	// saturated: per-issuer limits are independent.
	mustSubmit("renew_b1", "issuer_b", healthyB)
	healthyB.waitStarted()
	if got := rs.activeCount("issuer_b"); got != 1 {
		t.Fatalf("healthy issuer was blocked by saturated issuer: active for B=%d", got)
	}

	// And A's second job must still be waiting, not have jumped ahead.
	if got := rs.queuedCount(); got != 1 {
		t.Fatalf("expected issuer A's second job to remain queued, got queued=%d", got)
	}

	healthyB.allow()
	blockedA1.allow()
	blockedA2.allow()
	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatalf("scheduler did not drain: active=%d queued=%d", rs.activeCount(""), rs.queuedCount())
	}
}

// TestRenewalSchedulerPerIssuerOverride applies a map-based per-issuer
// limit instead of the default per-issuer limit.
func TestRenewalSchedulerPerIssuerOverride(t *testing.T) {
	rs := newRenewalScheduler(0, 1, map[string]int{"issuer_big": 3})
	t.Cleanup(rs.Stop)

	gates := make([]*jobGate, 4)
	for i := range gates {
		gates[i] = newJobGate()
		gate := gates[i]
		key := fmt.Sprintf("renew_big_%d", i)
		if err := rs.Submit(context.Background(), zap.NewNop(), key, "issuer_big", gate.job()); err != nil {
			t.Fatalf("Submit %s: %v", key, err)
		}
	}
	if !waitUntil(2*time.Second, func() bool {
		return rs.activeCount("issuer_big") == 3 && rs.queuedCount() == 1
	}) {
		t.Fatalf("override limit not applied: active=%d queued=%d",
			rs.activeCount("issuer_big"), rs.queuedCount())
	}
	for _, g := range gates {
		g.allow()
	}
	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatal("scheduler did not drain")
	}
}

// TestRenewalSchedulerCoalescesDuplicates verifies requirement #5: repeated
// submissions for the same logical identity merge into one job, and the
// merged job keeps the position of its first submission (it is not pushed to
// the back of the queue on every duplicate).
func TestRenewalSchedulerCoalescesDuplicates(t *testing.T) {
	rs := newRenewalScheduler(1, 0, nil) // global limit 1 so jobs queue up
	t.Cleanup(rs.Stop)

	head := newJobGate()
	waiter := newJobGate()

	if err := rs.Submit(context.Background(), zap.NewNop(), "renew_head", "issuer_a", head.job()); err != nil {
		t.Fatalf("Submit head: %v", err)
	}
	head.waitStarted()

	// First submission of the waiter takes queue position 1.
	if err := rs.Submit(context.Background(), zap.NewNop(), "renew_dup", "issuer_a", waiter.job()); err != nil {
		t.Fatalf("Submit waiter: %v", err)
	}
	// Repeated submissions of the same key while queued must be no-ops.
	for range 5 {
		if err := rs.Submit(context.Background(), zap.NewNop(), "renew_dup", "issuer_a", func(context.Context) error {
			t.Error("coalesced duplicate submission must not run its own job")
			return nil
		}); err != nil {
			t.Fatalf("duplicate Submit: %v", err)
		}
	}
	if got := rs.queuedCount(); got != 1 {
		t.Fatalf("duplicate submissions were not coalesced: queued=%d", got)
	}

	// Once the head finishes, exactly the one waiter job runs.
	head.allow()
	waiter.waitStarted()
	waiter.allow()
	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatal("scheduler did not drain")
	}
}

// TestRenewalSchedulerPreservesFIFOOrdering verifies the stable task order
// requirement: jobs start in submission order, not randomly or LIFO.
func TestRenewalSchedulerPreservesFIFOOrdering(t *testing.T) {
	rs := newRenewalScheduler(1, 0, nil)
	t.Cleanup(rs.Stop)

	const n = 5
	gates := make([]*jobGate, n)
	var orderMu sync.Mutex
	var order []int

	for i := range n {
		gates[i] = newJobGate()
		idx := i
		gate := gates[i]
		key := fmt.Sprintf("renew_fifo_%d", i)
		err := rs.Submit(context.Background(), zap.NewNop(), key, "issuer_a", func(ctx context.Context) error {
			orderMu.Lock()
			order = append(order, idx)
			orderMu.Unlock()
			return gate.job()(ctx)
		})
		if err != nil {
			t.Fatalf("Submit %s: %v", key, err)
		}
	}

	// With a single global slot, jobs must start one at a time and in
	// submission order. Each job records its index when it starts, then
	// blocks until released.
	gates[0].waitStarted()
	for i := range n {
		orderMu.Lock()
		startedCount := len(order)
		orderMu.Unlock()
		if startedCount != i+1 {
			t.Fatalf("job %d started out of order; start sequence so far: %v", i, order)
		}
		if order[i] != i {
			t.Fatalf("job start order wrong: got %v, want 0..%d", order, n-1)
		}
		gates[i].allow()
		// wait until this job has fully completed and the next one started
		if i < n-1 {
			gates[i+1].waitStarted()
		}
	}
	if !waitUntil(time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatal("scheduler did not drain")
	}
	orderMu.Lock()
	defer orderMu.Unlock()
	for i, got := range order {
		if got != i {
			t.Fatalf("jobs ran out of order: got %v, want 0..%d", order, n-1)
		}
	}
}

// TestRenewalSchedulerCancelReleasesQuotaAndGoroutine covers requirement #4:
// canceling a job while it is waiting for a slot removes it from the queue,
// immediately frees the reservation for another job, and leaves no goroutine
// behind. This is also the "no infinite queue jumping" guarantee: a canceled
// domain simply disappears rather than being retried ahead of peers.
func TestRenewalSchedulerCancelReleasesQuotaAndGoroutine(t *testing.T) {
	rs := newRenewalScheduler(1, 0, nil)
	t.Cleanup(rs.Stop)

	head := newJobGate()
	if err := rs.Submit(context.Background(), zap.NewNop(), "renew_head", "issuer_a", head.job()); err != nil {
		t.Fatalf("Submit head: %v", err)
	}
	head.waitStarted()

	ctx, cancel := context.WithCancel(context.Background())
	canceledGate := newJobGate()
	if err := rs.Submit(ctx, zap.NewNop(), "renew_canceled", "issuer_a", canceledGate.job()); err != nil {
		t.Fatalf("Submit canceled: %v", err)
	}
	replacement := newJobGate()
	if err := rs.Submit(context.Background(), zap.NewNop(), "renew_replacement", "issuer_a", replacement.job()); err != nil {
		t.Fatalf("Submit replacement: %v", err)
	}

	if !waitUntil(time.Second, func() bool { return rs.queuedCount() == 2 }) {
		t.Fatalf("expected two queued jobs, got %d", rs.queuedCount())
	}

	// Cancel the waiting job: it must leave the queue without ever running.
	cancel()
	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == 1 }) {
		t.Fatalf("canceled job was not removed from the queue: queued=%d", rs.queuedCount())
	}
	// Give the canceled job's goroutine time to (incorrectly) run, if it
	// were ever going to.
	time.Sleep(50 * time.Millisecond)
	select {
	case <-canceledGate.started:
		t.Fatal("canceled job started running after its context was canceled")
	default:
	}

	// Free the head slot; the replacement must be admitted (proving the
	// canceled job did not hold or leak any quota).
	head.allow()
	replacement.waitStarted()
	replacement.allow()

	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatalf("scheduler did not drain: active=%d queued=%d", rs.activeCount(""), rs.queuedCount())
	}
}

// TestRenewalSchedulerStopDrainsGoroutines verifies Stop abandons queued
// jobs, waits for running jobs, and leaves no scheduler goroutines behind.
func TestRenewalSchedulerStopDrainsGoroutines(t *testing.T) {
	rs := newRenewalScheduler(1, 0, nil)

	running := newJobGate()
	queued := newJobGate()

	if err := rs.Submit(context.Background(), zap.NewNop(), "renew_running", "issuer_a", running.job()); err != nil {
		t.Fatalf("Submit running: %v", err)
	}
	running.waitStarted()
	if err := rs.Submit(context.Background(), zap.NewNop(), "renew_queued", "issuer_a", queued.job()); err != nil {
		t.Fatalf("Submit queued: %v", err)
	}
	if !waitUntil(time.Second, func() bool { return rs.queuedCount() == 1 }) {
		t.Fatal("queued job never enqueued")
	}

	// Stop while one job is still running and another is queued. Stop must
	// block until the running job is released and finishes; the queued one
	// never runs.
	stopped := make(chan struct{})
	go func() { rs.Stop(); close(stopped) }()

	select {
	case <-stopped:
		t.Fatal("Stop returned while a job was still running")
	case <-time.After(50 * time.Millisecond):
	}

	running.allow()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the running job finished")
	}

	select {
	case <-queued.started:
		t.Fatal("queued job ran after the scheduler was stopped")
	default:
	}
	assertGoroutinesSettled(t)

	// Submitting after Stop is an error rather than a silent goroutine leak.
	if err := rs.Submit(context.Background(), zap.NewNop(), "renew_after_stop", "issuer_a", func(context.Context) error {
		return nil
	}); !errors.Is(err, errRenewalSchedulerStopped) {
		t.Fatalf("expected errRenewalSchedulerStopped after Stop, got %v", err)
	}

	// Stop is idempotent.
	rs.Stop()
}

// TestRetryAfterFromAndBackoffHonorsServerTime covers requirement #3: when a
// failure carries a server-mandated retry time, the backoff schedule waits
// until that time; the normal exponential interval is used otherwise, and an
// excessively large server value is capped.
func TestRetryAfterFromAndBackoffHonorsServerTime(t *testing.T) {
	base := fmt.Errorf("rate limited")
	rae := RetryAfterError{RetryAfter: time.Now().Add(10 * time.Minute), Err: base}

	if got, ok := retryAfterFrom(rae); !ok || got.IsZero() {
		t.Fatal("expected to extract a retry time from RetryAfterError")
	}
	if _, ok := retryAfterFrom(base); ok {
		t.Fatal("plain error must not report a retry time")
	}
	if !errors.Is(rae, base) {
		t.Fatal("RetryAfterError must unwrap to its underlying error")
	}

	rb := &renewalBackoff{}
	const name = "renew_retry_after"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Server asks for 10 minutes; the first local interval is 1 minute, so
	// the server's time wins.
	serverTime := now.Add(10 * time.Minute)
	if exhausted := rb.recordFailureWithRetryAfter(name, now, serverTime); exhausted {
		t.Fatal("unexpected exhaustion")
	}
	if rb.readyForAsOf(name, serverTime.Add(-time.Second)) {
		t.Fatal("job must not be ready before the server's retry time")
	}
	if !rb.readyForAsOf(name, serverTime) {
		t.Fatal("job must be ready at the server's retry time")
	}

	// A server time in the past cannot shorten the normal backoff: the
	// local interval still applies.
	rb.clear(name)
	rb.recordFailureWithRetryAfter(name, now, now.Add(-time.Minute))
	localDue := now.Add(retryIntervals[0])
	if rb.readyForAsOf(name, localDue.Add(-time.Millisecond)) {
		t.Fatal("past server time must not undercut the local backoff interval")
	}
	if !rb.readyForAsOf(name, localDue) {
		t.Fatal("expected normal local backoff when server time is in the past")
	}

	// An absurd server value is capped instead of parking the renewal forever.
	rb.clear(name)
	rb.recordFailureWithRetryAfter(name, now, now.Add(365*24*time.Hour))
	capDue := now.Add(maxRenewalRetryWait)
	if rb.readyForAsOf(name, capDue.Add(-time.Millisecond)) {
		t.Fatal("server retry time was not capped")
	}
	if !rb.readyForAsOf(name, capDue) {
		t.Fatal("expected readiness once the capped wait elapsed")
	}
}

// TestRenewalSchedulerGlobalAndIssuerLimitsInteract ensures both limits are
// enforced at once: the effective ceiling is the tighter of the global and
// the per-issuer budget.
func TestRenewalSchedulerGlobalAndIssuerLimitsInteract(t *testing.T) {
	// Global 2, per-issuer 1, two issuers.
	rs := newRenewalScheduler(2, 1, nil)
	t.Cleanup(rs.Stop)

	gates := make([]*jobGate, 4)
	for i := range gates {
		gates[i] = newJobGate()
		issuer := "issuer_a"
		if i%2 == 1 {
			issuer = "issuer_b"
		}
		key := fmt.Sprintf("renew_mix_%d", i)
		if err := rs.Submit(context.Background(), zap.NewNop(), key, issuer, gates[i].job()); err != nil {
			t.Fatalf("Submit %s: %v", key, err)
		}
	}

	if !waitUntil(2*time.Second, func() bool {
		return rs.activeCount("") == 2 &&
			rs.activeCount("issuer_a") == 1 &&
			rs.activeCount("issuer_b") == 1 &&
			rs.queuedCount() == 2
	}) {
		t.Fatalf("limits not jointly enforced: total=%d a=%d b=%d queued=%d",
			rs.activeCount(""), rs.activeCount("issuer_a"), rs.activeCount("issuer_b"), rs.queuedCount())
	}
	for _, g := range gates {
		g.allow()
	}
	if !waitUntil(2*time.Second, func() bool { return rs.queuedCount() == 0 && rs.activeCount("") == 0 }) {
		t.Fatal("scheduler did not drain")
	}
}
