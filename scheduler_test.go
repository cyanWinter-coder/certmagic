package certmagic

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestMaintenanceSchedulerPartitionIsolation verifies that a blocked task
// in one issuer's partition does not prevent tasks of another issuer from
// running: each partition has its own concurrency quota.
func TestMaintenanceSchedulerPartitionIsolation(t *testing.T) {
	sched := newMaintenanceScheduler(1, nil)
	defer sched.stop(time.Second)

	blockA := make(chan struct{})
	aStarted := make(chan struct{})
	var bRan atomic.Bool

	sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "issuer-a", identity: "iso_a",
		run: func(ctx context.Context) error {
			close(aStarted)
			select {
			case <-blockA:
			case <-ctx.Done():
			}
			return nil
		},
	})
	select {
	case <-aStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("issuer A's task never started")
	}

	// issuer A's only slot is occupied and blocked; issuer B must still run
	sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "issuer-b", identity: "iso_b",
		run: func(context.Context) error { bRan.Store(true); return nil },
	})
	if !waitUntil(2*time.Second, bRan.Load) {
		t.Fatal("issuer B's task did not run while issuer A's task was blocked; partitions are not isolated")
	}
	close(blockA)
}

// TestMaintenanceSchedulerPriorityOrder verifies that renewal and OCSP
// tasks are each scheduled by their own deadline (certificate expiry vs.
// staple NextUpdate), earliest first, and that renewals win ties.
func TestMaintenanceSchedulerPriorityOrder(t *testing.T) {
	sched := newMaintenanceScheduler(1, nil)
	defer sched.stop(time.Second)

	gate := make(chan struct{})
	gateStarted := make(chan struct{})
	var mu sync.Mutex
	var order []string
	record := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return nil
		}
	}

	// occupy the partition's only slot so the following tasks queue up
	// and their relative order is determined purely by priority
	sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "ca", identity: "prio_gate",
		run: func(ctx context.Context) error {
			close(gateStarted)
			select {
			case <-gate:
			case <-ctx.Done():
			}
			return nil
		},
	})
	select {
	case <-gateStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("gate task never started")
	}

	now := time.Now()
	sched.submit(maintenanceTask{kind: taskKindRenewal, issuer: "ca", identity: "prio_renew_late",
		deadline: renewalPriority(now.Add(2 * time.Hour)), run: record("renew_late")})
	sched.submit(maintenanceTask{kind: taskKindOCSP, issuer: "ca", identity: "prio_ocsp_mid",
		deadline: ocspPriority(now.Add(time.Hour)), run: record("ocsp_mid")})
	sched.submit(maintenanceTask{kind: taskKindOCSP, issuer: "ca", identity: "prio_ocsp_stale",
		deadline: ocspPriority(now.Add(-time.Hour)), run: record("ocsp_stale")})
	// same deadline as ocsp_mid, but a renewal: renewals sort first
	sched.submit(maintenanceTask{kind: taskKindRenewal, issuer: "ca", identity: "prio_renew_mid",
		deadline: renewalPriority(now.Add(time.Hour)), run: record("renew_mid")})

	close(gate)
	if !waitUntil(2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(order) == 4
	}) {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("not all tasks ran; order so far: %v", order)
	}

	want := []string{"ocsp_stale", "renew_mid", "ocsp_mid", "renew_late"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("wrong execution order: got %v, want %v", order, want)
		}
	}
}

// TestMaintenanceSchedulerMergesDuplicateIdentities verifies that a second
// task submitted with an identity that is already queued merges into the
// queued task: the work runs only once, both submitters' handles settle,
// and the merged task adopts the earlier deadline.
func TestMaintenanceSchedulerMergesDuplicateIdentities(t *testing.T) {
	sched := newMaintenanceScheduler(1, nil)
	defer sched.stop(time.Second)

	gate := make(chan struct{})
	gateStarted := make(chan struct{})
	sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "ca", identity: "merge_gate",
		run: func(ctx context.Context) error {
			close(gateStarted)
			select {
			case <-gate:
			case <-ctx.Done():
			}
			return nil
		},
	})
	select {
	case <-gateStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("gate task never started")
	}

	var mu sync.Mutex
	var order []string
	record := func(name string) func(context.Context) error {
		return func(context.Context) error {
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			return nil
		}
	}

	now := time.Now()
	h1 := sched.submit(maintenanceTask{kind: taskKindOCSP, issuer: "ca", identity: "merge_dup",
		deadline: now.Add(10 * time.Hour), run: record("dup")})
	// duplicate identity with an EARLIER deadline: merges into the queued
	// task and pulls it ahead of "mid" instead of running twice
	h2 := sched.submit(maintenanceTask{kind: taskKindOCSP, issuer: "ca", identity: "merge_dup",
		deadline: now.Add(time.Hour), run: record("dup_second_must_not_run")})
	h3 := sched.submit(maintenanceTask{kind: taskKindOCSP, issuer: "ca", identity: "merge_mid",
		deadline: now.Add(5 * time.Hour), run: record("mid")})

	close(gate)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h1.wait(ctx)
	h2.wait(ctx)
	h3.wait(ctx)

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "dup" || order[1] != "mid" {
		t.Fatalf("expected merged task to run exactly once, ahead of mid (earlier deadline won); got %v", order)
	}
}

// TestMaintenanceSchedulerNotBefore verifies that a task with a not-before
// time (backoff) is not started before that time arrives.
func TestMaintenanceSchedulerNotBefore(t *testing.T) {
	sched := newMaintenanceScheduler(1, nil)
	defer sched.stop(time.Second)

	var ranAt atomic.Int64
	h := sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "ca", identity: "nb_delayed",
		notBefore: time.Now().Add(150 * time.Millisecond),
		run: func(context.Context) error {
			ranAt.Store(time.Now().UnixNano())
			return nil
		},
	})

	time.Sleep(50 * time.Millisecond)
	if ranAt.Load() != 0 {
		t.Fatal("task ran before its not-before time")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	h.wait(ctx)
	if ranAt.Load() == 0 {
		t.Fatal("task never ran after its not-before time")
	}
}

// TestMaintenanceSchedulerStopCancelsAndReleasesQuota verifies that stop
// cancels started tasks after the grace period, that the tasks' partition
// quota is released (not leaked) when they unwind, and that new submissions
// are rejected with an immediately-settled handle.
func TestMaintenanceSchedulerStopCancelsAndReleasesQuota(t *testing.T) {
	sched := newMaintenanceScheduler(1, nil)

	started := make(chan struct{})
	ctxCancelled := make(chan struct{})
	sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "ca", identity: "stop_blocking",
		run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(ctxCancelled)
			return ctx.Err()
		},
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("task never started")
	}

	stopDone := make(chan struct{})
	go func() {
		sched.stop(50 * time.Millisecond)
		close(stopDone)
	}()

	select {
	case <-ctxCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not cancel the running task's context after the grace period")
	}
	select {
	case <-stopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stop did not return after the running task unwound")
	}

	sched.mu.Lock()
	running := sched.partitions["ca"].running
	sched.mu.Unlock()
	if running != 0 {
		t.Fatalf("cancelled task leaked its partition quota: running=%d, want 0", running)
	}

	var ran atomic.Bool
	h := sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "ca", identity: "stop_late",
		run: func(context.Context) error { ran.Store(true); return nil },
	})
	select {
	case <-h.done:
	default:
		t.Fatal("expected handle of a task submitted after stop to be settled immediately")
	}
	if ran.Load() {
		t.Fatal("task submitted after stop ran anyway")
	}
}

// TestMaintenanceSchedulerStopDropsQueuedTasks verifies that stop drops
// tasks that were queued but never started, settling their handles so
// batch waiters do not block forever.
func TestMaintenanceSchedulerStopDropsQueuedTasks(t *testing.T) {
	sched := newMaintenanceScheduler(1, nil)

	started := make(chan struct{})
	sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "ca", identity: "drop_gate",
		run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		},
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("gate task never started")
	}

	var queuedRan atomic.Bool
	h := sched.submit(maintenanceTask{
		kind: taskKindOCSP, issuer: "ca", identity: "drop_queued",
		run: func(context.Context) error { queuedRan.Store(true); return nil },
	})

	sched.stop(50 * time.Millisecond)

	if queuedRan.Load() {
		t.Fatal("queued task ran after stop; it should have been dropped")
	}
	select {
	case <-h.done:
	default:
		t.Fatal("dropped task's handle was not settled")
	}
}

// TestMaintenanceSchedulerBatchHandlesSettle verifies the mechanism behind
// the OCSP maintenance pass's commit boundary: waiting on the handles of a
// batch of submitted tasks returns only after every task has completed.
func TestMaintenanceSchedulerBatchHandlesSettle(t *testing.T) {
	sched := newMaintenanceScheduler(2, nil)
	defer sched.stop(time.Second)

	var completed atomic.Int32
	var handles []maintenanceTaskHandle
	for i := 0; i < 10; i++ {
		h := sched.submit(maintenanceTask{
			kind:     taskKindOCSP,
			issuer:   fmt.Sprintf("issuer-%d", i%3),
			identity: fmt.Sprintf("batch_%d", i),
			run: func(context.Context) error {
				completed.Add(1)
				return nil
			},
		})
		handles = append(handles, h)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, h := range handles {
		h.wait(ctx)
	}
	if got := completed.Load(); got != 10 {
		t.Fatalf("commit boundary reached before all tasks settled: completed=%d, want 10", got)
	}
}

// TestRenewalBackoffHonorsServerWaitWithCap verifies that a failed
// renewal's next attempt honors a server-requested wait (e.g. ARI
// Retry-After) when it exceeds our own backoff interval, and that the
// effective wait is capped so a server cannot postpone renewal forever.
func TestRenewalBackoffHonorsServerWaitWithCap(t *testing.T) {
	rb := &renewalBackoff{}
	const name = "renew_example.com"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	nextAttempt := func() time.Time {
		rb.mu.Lock()
		defer rb.mu.Unlock()
		return rb.state[name].nextAttempt
	}

	// server wait shorter than our own interval: our interval wins
	rb.recordFailureWithServerWait(name, now, time.Second)
	if got, want := nextAttempt(), now.Add(retryIntervals[0]); !got.Equal(want) {
		t.Fatalf("short server wait: nextAttempt=%v, want %v", got, want)
	}

	// server wait longer than our interval: honored
	rb.clear(name)
	rb.recordFailureWithServerWait(name, now, 3*time.Hour)
	if got, want := nextAttempt(), now.Add(3*time.Hour); !got.Equal(want) {
		t.Fatalf("long server wait: nextAttempt=%v, want %v", got, want)
	}

	// absurd server wait: capped at maxRenewalBackoff
	rb.clear(name)
	rb.recordFailureWithServerWait(name, now, 1000*time.Hour)
	if got, want := nextAttempt(), now.Add(maxRenewalBackoff); !got.Equal(want) {
		t.Fatalf("excessive server wait: nextAttempt=%v, want %v (capped)", got, want)
	}
}

// gatedIssuer is a fake Issuer whose Issue calls block until the gate is
// released (or the context is cancelled), simulating an issuer that is
// hanging. It is used to prove issuer-partition isolation end to end.
type gatedIssuer struct {
	started chan struct{}
	once    sync.Once
	gate    chan struct{}
	calls   atomic.Int32
}

func (g *gatedIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	g.calls.Add(1)
	g.once.Do(func() { close(g.started) })
	select {
	case <-g.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, fmt.Errorf("simulated issuer outage")
}

func (g *gatedIssuer) IssuerKey() string { return "gated_test_issuer" }

// seedExpiringManagedCert builds an already-expired managed certificate for
// domain, stores it as the current cert resource for issuer, and returns
// the Config and in-cache Certificate to drive queueRenewalTask with.
func seedExpiringManagedCert(t *testing.T, certCache *Cache, issuer Issuer, domain string) (*Config, Certificate) {
	t.Helper()

	cfg := &Config{
		Issuers:          []Issuer{issuer},
		Storage:          &FileStorage{Path: t.TempDir()},
		Logger:           defaultTestLogger,
		DisableARI:       true, // keep the renewal-needed check to plain expiration logic
		ReusePrivateKeys: true, // avoid needing a KeySource for a fresh key
		certCache:        certCache,
	}
	cfg.OCSP.DisableStapling = true

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-60 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour), // already expired
	}
	leaf, priv, certPEM := mustIssueTestCertificate(t, tmpl, nil, nil)

	privPEM, err := PEMEncodePrivateKey(priv)
	if err != nil {
		t.Fatalf("encoding private key: %v", err)
	}

	certRes := CertificateResource{
		SANs:           []string{domain},
		CertificatePEM: certPEM,
		PrivateKeyPEM:  privPEM,
		issuerKey:      issuer.IssuerKey(),
	}
	ctx := context.Background()
	if err := cfg.saveCertResource(ctx, issuer, certRes); err != nil {
		t.Fatalf("seeding cert resource in storage: %v", err)
	}

	oldCert := Certificate{
		Names:     []string{domain},
		managed:   true,
		issuerKey: issuer.IssuerKey(),
	}
	oldCert.Leaf = leaf
	return cfg, oldCert
}

// TestQueueRenewalTaskIssuerPartitionsAreIsolated verifies end to end that
// when one issuer's renewal attempts hang (e.g. the CA is unreachable and
// connections stall), renewals of certificates from another issuer still
// proceed: a single failing issuer can no longer occupy the whole
// maintenance queue.
func TestQueueRenewalTaskIssuerPartitionsAreIsolated(t *testing.T) {
	certCache := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}

	gated := &gatedIssuer{started: make(chan struct{}), gate: make(chan struct{})}
	failing := &failingIssuer{err: fmt.Errorf("simulated DNS-01 challenge failure")}

	cfgA, certA := seedExpiringManagedCert(t, certCache, gated, "blocked-example.com")
	cfgB, certB := seedExpiringManagedCert(t, certCache, failing, "free-example.com")

	jobA, jobB := "renew_blocked-example.com", "renew_free-example.com"
	renewalRetrySchedule.clear(jobA)
	renewalRetrySchedule.clear(jobB)
	t.Cleanup(func() {
		renewalRetrySchedule.clear(jobA)
		renewalRetrySchedule.clear(jobB)
	})

	ctx := context.Background()

	// issuer A's renewal hangs inside Issue, holding its partition's slot
	if err := certCache.queueRenewalTask(ctx, certA, cfgA); err != nil {
		t.Fatalf("queueRenewalTask (issuer A): %v", err)
	}
	select {
	case <-gated.started:
	case <-time.After(2 * time.Second):
		t.Fatal("issuer A's renewal never started")
	}

	// issuer B's renewal must still run: it lives in a different partition
	if err := certCache.queueRenewalTask(ctx, certB, cfgB); err != nil {
		t.Fatalf("queueRenewalTask (issuer B): %v", err)
	}
	if !waitUntil(2*time.Second, func() bool { return failing.calls.Load() == 1 }) {
		t.Fatal("issuer B's renewal did not run while issuer A's renewal was blocked; issuers are not isolated")
	}

	// let issuer A's attempt unwind, then wait for its failure to be
	// recorded so no state leaks into other tests
	close(gated.gate)
	waitUntil(time.Second, func() bool { return !renewalRetrySchedule.readyFor(jobA) })
	certCache.stopMaintenanceScheduler(time.Second)
}
