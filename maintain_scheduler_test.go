package certmagic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedIssuer is a fake Issuer for maintenance-level tests. Each call to
// Issue runs the next scripted result (an error, possibly a RetryAfterError),
// falling back to the final result once the script is exhausted. It records
// the peak number of concurrent Issue calls.
type scriptedIssuer struct {
	key    string
	mu     sync.Mutex
	script []error
	active atomic.Int32
	peak   atomic.Int32
	calls  atomic.Int32
}

func (si *scriptedIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	cur := si.active.Add(1)
	for {
		peak := si.peak.Load()
		if cur <= peak || si.peak.CompareAndSwap(peak, cur) {
			break
		}
	}
	defer si.active.Add(-1)
	si.calls.Add(1)

	si.mu.Lock()
	var err error
	idx := int(si.calls.Load()) - 1
	if idx < len(si.script) {
		err = si.script[idx]
	} else if len(si.script) > 0 {
		err = si.script[len(si.script)-1]
	}
	si.mu.Unlock()

	if err != nil {
		return nil, err
	}

	// Success: mint a fresh self-signed leaf so the renewal path has a
	// complete PEM resource to store and reload.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	return &IssuedCertificate{
		Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

func (si *scriptedIssuer) IssuerKey() string { return si.key }

func (si *scriptedIssuer) peakConcurrency() int32 { return si.peak.Load() }

// blockingIssuer wraps scriptedIssuer so each Issue blocks until release is
// closed, giving a test deterministic control over in-flight renewal jobs.
type blockingIssuer struct {
	*scriptedIssuer
	release chan struct{}
	entered atomic.Int32
}

func (bi *blockingIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	bi.entered.Add(1)
	select {
	case <-bi.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return bi.scriptedIssuer.Issue(ctx, csr)
}

// newMaintenanceTestCache builds a bare Cache wired to a renewal scheduler
// with the requested limits, plus a Config using issuer and temp storage.
func newMaintenanceTestCache(t *testing.T, global, perIssuer int, issuer Issuer) (*Cache, *Config) {
	t.Helper()
	certCache := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
		options: CacheOptions{
			RenewCheckInterval:             DefaultRenewCheckInterval,
			OCSPCheckInterval:              DefaultOCSPCheckInterval,
			RenewalMaxConcurrency:          global,
			RenewalMaxConcurrencyPerIssuer: perIssuer,
			GetConfigForCert:               func(Certificate) (*Config, error) { return nil, nil },
		},
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}
	certCache.renewalScheduler = certCache.newRenewalSchedulerFromOptions()
	t.Cleanup(certCache.renewalScheduler.Stop)

	issuers := []Issuer{issuer}
	cfg := &Config{
		Issuers:          issuers,
		Storage:          &FileStorage{Path: t.TempDir()},
		Logger:           defaultTestLogger,
		DisableARI:       true,
		ReusePrivateKeys: true,
		certCache:        certCache,
	}
	cfg.OCSP.DisableStapling = true
	return certCache, cfg
}

// seedExpiredCert stores an expired self-signed certificate resource for
// domain and returns the in-memory Certificate representing it.
func seedExpiredCert(t *testing.T, cfg *Config, issuer Issuer, domain string) Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-60 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
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
	if err := cfg.saveCertResource(context.Background(), issuer, certRes); err != nil {
		t.Fatalf("seeding cert resource: %v", err)
	}
	cert := Certificate{
		Names:     []string{domain},
		managed:   true,
		issuerKey: issuer.IssuerKey(),
	}
	cert.Leaf = leaf
	return cert
}

// TestMaintenanceRestartBurstRespectsGlobalLimit is the end-to-end version of
// the restart scenario: after a restart, a batch of expiring domains is
// queued at once and the global renewal ceiling must hold, while every domain
// is still renewed as slots free up.
func TestMaintenanceRestartBurstRespectsGlobalLimit(t *testing.T) {
	const domains = 6
	const limit = 2

	scripted := &scriptedIssuer{key: "burst_test_issuer"}
	blocking := &blockingIssuer{scriptedIssuer: scripted, release: make(chan struct{})}
	certCache, cfg := newMaintenanceTestCache(t, limit, 0, blocking)

	var certs []Certificate
	for i := range domains {
		domain := fmt.Sprintf("burst%d.example", i)
		cert := seedExpiredCert(t, cfg, blocking, domain)
		certs = append(certs, cert)
		renewalRetrySchedule.clear("renew_" + domain)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	for _, cert := range certs {
		if err := certCache.queueRenewalTask(ctx, cert, cfg); err != nil {
			t.Fatalf("queueRenewalTask: %v", err)
		}
	}

	// Exactly `limit` jobs should be in flight; the rest remain queued.
	if !waitUntil(2*time.Second, func() bool {
		return certCache.renewalScheduler.activeCount("") == limit &&
			certCache.renewalScheduler.queuedCount() == domains-limit
	}) {
		t.Fatalf("expected %d active / %d queued, got active=%d queued=%d",
			limit, domains-limit,
			certCache.renewalScheduler.activeCount(""),
			certCache.renewalScheduler.queuedCount())
	}
	if got := scripted.peakConcurrency(); got > limit {
		t.Fatalf("peak renewal concurrency %d exceeded limit %d", got, limit)
	}

	// Release all in-flight calls; every queued job must then run to success.
	close(blocking.release)
	if !waitUntil(3*time.Second, func() bool {
		return certCache.renewalScheduler.queuedCount() == 0 &&
			certCache.renewalScheduler.activeCount("") == 0
	}) {
		t.Fatalf("burst did not drain: active=%d queued=%d",
			certCache.renewalScheduler.activeCount(""),
			certCache.renewalScheduler.queuedCount())
	}
	if got := scripted.calls.Load(); got != domains {
		t.Fatalf("expected %d issuance attempts, got %d", domains, got)
	}
	if got := scripted.peakConcurrency(); got > limit {
		t.Fatalf("peak concurrency %d exceeded limit %d", got, limit)
	}
}

// TestMaintenanceLocalIssuerFailureDoesNotBlockOthers proves requirement #2
// at the maintenance layer: a domain at a failing issuer backs off and cannot
// re-insert itself ahead of other work, while a domain at a healthy issuer
// renews normally. Each domain uses a separate cache/config so each has its
// own issuer set and storage, mirroring two independent CA configurations.
func TestMaintenanceLocalIssuerFailureDoesNotBlockOthers(t *testing.T) {
	bad := &scriptedIssuer{key: "bad_issuer", script: []error{fmt.Errorf("simulated CA outage")}}
	good := &scriptedIssuer{key: "good_issuer"}

	badCache, badCfg := newMaintenanceTestCache(t, 0, 1, bad)
	goodCache, goodCfg := newMaintenanceTestCache(t, 0, 1, good)

	badDomain := seedExpiredCert(t, badCfg, bad, "bad.example")
	goodDomain := seedExpiredCert(t, goodCfg, good, "good.example")
	renewalRetrySchedule.clear("renew_bad.example")
	renewalRetrySchedule.clear("renew_good.example")

	ctx := context.Background()

	// The failing domain attempts once and enters backoff.
	if err := badCache.queueRenewalTask(ctx, badDomain, badCfg); err != nil {
		t.Fatalf("queue bad: %v", err)
	}
	if !waitUntil(2*time.Second, func() bool { return bad.calls.Load() == 1 }) {
		t.Fatalf("bad issuer was never attempted, calls=%d", bad.calls.Load())
	}
	if !waitUntil(time.Second, func() bool { return !renewalRetrySchedule.readyFor("renew_bad.example") }) {
		t.Fatal("failed domain should be in backoff")
	}

	// A second maintenance tick must NOT re-attempt the bad domain (backoff),
	// so it cannot keep inserting itself ahead of other work.
	if err := badCache.queueRenewalTask(ctx, badDomain, badCfg); err != nil {
		t.Fatalf("re-queue bad: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := bad.calls.Load(); got != 1 {
		t.Fatalf("backed-off domain jumped the queue with a new attempt: calls=%d", got)
	}

	// The healthy issuer's domain renews despite the other issuer's outage.
	if err := goodCache.queueRenewalTask(ctx, goodDomain, goodCfg); err != nil {
		t.Fatalf("queue good: %v", err)
	}
	if !waitUntil(2*time.Second, func() bool { return good.calls.Load() == 1 }) {
		t.Fatalf("healthy issuer was blocked by failing issuer, calls=%d", good.calls.Load())
	}
	if !waitUntil(time.Second, func() bool {
		return goodCache.renewalScheduler.activeCount("") == 0
	}) {
		t.Fatal("healthy renewal did not finish")
	}
}

// TestMaintenanceRetryAfterErrorDrivesBackoff verifies requirement #3
// end-to-end: when the issuer fails with a RetryAfterError, the domain's next
// attempt waits for the server's time rather than the shorter local interval.
func TestMaintenanceRetryAfterErrorDrivesBackoff(t *testing.T) {
	serverRetryAt := time.Now().Add(10 * time.Minute)
	issuer := &scriptedIssuer{
		key:    "ra_issuer",
		script: []error{RetryAfterError{RetryAfter: serverRetryAt, Err: fmt.Errorf("rate limited")}},
	}
	certCache, cfg := newMaintenanceTestCache(t, 0, 0, issuer)
	domain := seedExpiredCert(t, cfg, issuer, "ra.example")
	jobName := "renew_ra.example"
	renewalRetrySchedule.clear(jobName)
	t.Cleanup(func() { renewalRetrySchedule.clear(jobName) })

	if err := certCache.queueRenewalTask(context.Background(), domain, cfg); err != nil {
		t.Fatalf("queueRenewalTask: %v", err)
	}
	if !waitUntil(2*time.Second, func() bool { return issuer.calls.Load() == 1 }) {
		t.Fatal("issuer was never attempted")
	}
	if !waitUntil(time.Second, func() bool { return !renewalRetrySchedule.readyFor(jobName) }) {
		t.Fatal("expected backoff after server-announced wait")
	}

	// The scheduled next attempt must honor the server's 10-minute time
	// (which is longer than the first local 1-minute interval).
	renewalRetrySchedule.mu.Lock()
	st := renewalRetrySchedule.state[jobName]
	renewalRetrySchedule.mu.Unlock()
	if st == nil {
		t.Fatal("no backoff state recorded")
	}
	if st.nextAttempt.Before(serverRetryAt.Add(-time.Second)) {
		t.Fatalf("next attempt %v scheduled before server retry time %v", st.nextAttempt, serverRetryAt)
	}
}

// TestMaintenanceCanceledQueuedRenewalReleasesSlot verifies requirement #4
// through the real maintenance entry point: canceling a renewal still waiting
// for a concurrency slot removes it and lets the next domain take the slot.
func TestMaintenanceCanceledQueuedRenewalReleasesSlot(t *testing.T) {
	scripted := &scriptedIssuer{key: "cancel_issuer"}
	blocking := &blockingIssuer{scriptedIssuer: scripted, release: make(chan struct{})}
	certCache, cfg := newMaintenanceTestCache(t, 1, 0, blocking)

	head := seedExpiredCert(t, cfg, blocking, "head.example")
	waiter := seedExpiredCert(t, cfg, blocking, "waiter.example")
	for _, d := range []string{"head.example", "waiter.example"} {
		renewalRetrySchedule.clear("renew_" + d)
	}

	headCtx, headCancel := context.WithCancel(context.Background())
	defer headCancel()
	if err := certCache.queueRenewalTask(headCtx, head, cfg); err != nil {
		t.Fatalf("queue head: %v", err)
	}
	if !waitUntil(2*time.Second, func() bool { return blocking.entered.Load() == 1 }) {
		t.Fatal("head renewal never started")
	}

	waiterCtx, waiterCancel := context.WithCancel(context.Background())
	if err := certCache.queueRenewalTask(waiterCtx, waiter, cfg); err != nil {
		t.Fatalf("queue waiter: %v", err)
	}
	if !waitUntil(time.Second, func() bool { return certCache.renewalScheduler.queuedCount() == 1 }) {
		t.Fatal("waiter never queued")
	}

	// Cancel the waiter before it starts; its slot reservation must vanish.
	waiterCancel()
	if !waitUntil(2*time.Second, func() bool { return certCache.renewalScheduler.queuedCount() == 0 }) {
		t.Fatal("canceled queued renewal was not removed")
	}

	// Finish the head; nothing else should run.
	close(blocking.release)
	if !waitUntil(2*time.Second, func() bool {
		return certCache.renewalScheduler.activeCount("") == 0 &&
			certCache.renewalScheduler.queuedCount() == 0
	}) {
		t.Fatal("scheduler did not settle after cancellation")
	}
	if got := scripted.calls.Load(); got != 1 {
		t.Fatalf("expected only the head to attempt issuance, got %d", got)
	}
}
