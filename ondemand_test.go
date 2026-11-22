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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

// resetCertApplications empties the process-wide application registry so
// tests start from a known state and registry entries from one test cannot
// satisfy or block another.
func resetCertApplications(t *testing.T) {
	t.Helper()
	certApplications.mu.Lock()
	for name, app := range certApplications.applications {
		delete(certApplications.applications, name)
		select {
		case <-app.done:
		default:
			close(app.done)
		}
	}
	certApplications.mu.Unlock()
	t.Cleanup(func() {
		certApplications.mu.Lock()
		certApplications.applications = make(map[string]*onDemandApplication)
		certApplications.mu.Unlock()
	})
}

// blockingIssuer is a test Issuer whose Issue call blocks until release is
// closed, letting a test hold an in-flight application while it arranges
// waiters and cancels contexts. It returns a real, parseable certificate so
// the full obtain -> storage -> cache publish path runs end to end.
type blockingIssuer struct {
	key        string
	issueCalls atomic.Int32
	started    chan struct{} // closed once on the first Issue call
	release    chan struct{}
	fail       error // when non-nil, Issue returns it instead of a certificate
	once       sync.Once
}

func newBlockingIssuer() *blockingIssuer {
	return &blockingIssuer{
		key:     "blocking-test-issuer",
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *blockingIssuer) IssuerKey() string { return b.key }

func (b *blockingIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*IssuedCertificate, error) {
	b.issueCalls.Add(1)
	b.once.Do(func() { close(b.started) })
	if b.fail != nil {
		// A permanent failure returns immediately, like a CA rejection would;
		// do not block on release so retry attempts also finish promptly.
		return nil, b.fail
	}
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// Mirror a real CA: sign a leaf certificate carrying the CSR's public key
	// and SANs, so the result pairs with the private key the obtain flow stored.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("generating test issuer key: " + err.Error())
	}
	dnsNames := csr.DNSNames
	if len(dnsNames) == 0 {
		dnsNames = []string{onDemandTestDomain}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, key)
	if err != nil {
		panic("creating test certificate: " + err.Error())
	}
	return &IssuedCertificate{Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

const onDemandTestDomain = "ondemand.example"

// newOnDemandTestConfig builds a Config with an on-demand DecisionFunc that
// always allows, a temp FileStorage and the given issuer, backed by a real
// cache so the obtain -> storage -> cache publication path is exercised.
func newOnDemandTestConfig(t *testing.T, issuer Issuer) *Config {
	t.Helper()
	var cfg *Config
	cache := NewCache(CacheOptions{
		GetConfigForCert: func(Certificate) (*Config, error) { return cfg, nil },
		Logger:           zap.NewNop(),
	})
	t.Cleanup(cache.Stop)

	cfg = New(cache, Config{
		Storage: &FileStorage{Path: t.TempDir()},
		Logger:  zap.NewNop(),
		Issuers: []Issuer{issuer},
		OnDemand: &OnDemandConfig{
			DecisionFunc: func(context.Context, string) error { return nil },
		},
		OCSP: OCSPConfig{DisableStapling: true},
	})
	return cfg
}

func onDemandHello(serverName string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{ServerName: serverName, Conn: testConn{}}
}

// TestCanonicalNameFoldsIdentity verifies the single normalization rule that
// keys every shared on-demand application: case, the optional DNS root label
// (trailing dots) and IDNA encoding all converge on one identity.
func TestCanonicalNameFoldsIdentity(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase passthrough", "example.com", "example.com"},
		{"uppercase folded", "EXAMPLE.COM", "example.com"},
		{"mixed case folded", "ExAmPLe.CoM", "example.com"},
		{"single trailing dot removed", "example.com.", "example.com"},
		{"multiple trailing dots removed", "example.com...", "example.com"},
		{"whitespace trimmed", "  example.com  ", "example.com"},
		{"IDN to punycode", "bücher.example", "xn--bcher-kva.example"},
		{"upper-case IDN to punycode", "BÜCHER.Example", "xn--bcher-kva.example"},
		{"punycode passthrough", "xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"IDN with trailing dot", "bücher.example.", "xn--bcher-kva.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalName(tc.in)
			if err != nil {
				t.Fatalf("canonicalName(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("canonicalName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	// All variants of one identity must converge on the exact same key, which
	// is what makes them share a single application slot.
	variants := []string{
		"example.com", "Example.COM", "EXAMPLE.com.", "  example.com.  ",
	}
	first, err := canonicalName(variants[0])
	if err != nil {
		t.Fatalf("canonicalName(%q): %v", variants[0], err)
	}
	for _, v := range variants[1:] {
		got, err := canonicalName(v)
		if err != nil {
			t.Fatalf("canonicalName(%q): %v", v, err)
		}
		if got != first {
			t.Errorf("identity %q normalized to %q, want shared key %q", v, got, first)
		}
	}
}

// TestOnDemandApplicationSharedAcrossEquivalentNames verifies requirement (1):
// handshakes whose SNI differs only in case/trailing dot join one shared
// application and trigger exactly one issuance.
func TestOnDemandApplicationSharedAcrossEquivalentNames(t *testing.T) {
	resetCertApplications(t)
	issuer := newBlockingIssuer()
	cfg := newOnDemandTestConfig(t, issuer)

	const waiters = 4
	errs := make(chan error, waiters)
	names := []string{
		"ondemand.example",
		"ONDEMAND.EXAMPLE",
		"OnDemand.Example.",
		"  ondemand.example.  ",
	}

	// First handshake becomes the leader and blocks inside Issue.
	go func() {
		_, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(names[0]), true)
		errs <- err
	}()
	<-issuer.started

	// The remaining equivalent identities must join as waiters, not leaders.
	for _, n := range names[1:] {
		go func(serverName string) {
			_, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(serverName), true)
			errs <- err
		}(n)
	}

	if !waitUntil(time.Second, func() bool {
		certApplications.mu.Lock()
		app := certApplications.applications[onDemandTestDomain]
		certApplications.mu.Unlock()
		return app != nil
	}) {
		t.Fatal("expected one shared application under the canonical name")
	}

	// Give waiters time to (incorrectly, in a regression) spawn extra
	// applications, then assert the registry still holds exactly one.
	time.Sleep(50 * time.Millisecond)
	certApplications.mu.Lock()
	appCount := len(certApplications.applications)
	certApplications.mu.Unlock()
	if appCount != 1 {
		t.Errorf("expected exactly 1 in-flight application, got %d", appCount)
	}

	close(issuer.release)
	for i := 0; i < waiters; i++ {
		if err := <-errs; err != nil {
			t.Errorf("handshake %d failed: %v", i, err)
		}
	}

	if got := issuer.issueCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 issuance for equivalent names, got %d", got)
	}

	// The completed application must have released its slot.
	if !waitUntil(time.Second, func() bool {
		certApplications.mu.Lock()
		_, ok := certApplications.applications[onDemandTestDomain]
		certApplications.mu.Unlock()
		return !ok
	}) {
		t.Error("application slot was not released after success")
	}
}

// TestOnDemandLeaderCancellationDoesNotCancelIssuance verifies requirement
// (2): when the first waiter (the leader's triggering handshake) disconnects,
// the in-flight issuance continues to completion; later waiters still receive
// the certificate. The issuance work runs on a context detached from the
// handshakes, so the canceled first handshake cannot abort it.
func TestOnDemandLeaderCancellationDoesNotCancelIssuance(t *testing.T) {
	resetCertApplications(t)
	issuer := newBlockingIssuer()
	cfg := newOnDemandTestConfig(t, issuer)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() {
		_, err := cfg.getCertDuringHandshake(leaderCtx, onDemandHello(onDemandTestDomain), true)
		leaderErr <- err
	}()
	<-issuer.started

	// A second handshake parks behind the same application.
	waiterErr := make(chan error, 1)
	go func() {
		_, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
		waiterErr <- err
	}()
	time.Sleep(50 * time.Millisecond)

	// The leader's client gives up. The shared application must keep running:
	// the leader goroutine is now doing work on a detached context, so it does
	// not return yet and the issuance is neither canceled nor restarted.
	cancelLeader()
	select {
	case <-leaderErr:
		t.Fatal("leader returned while the detached issuance was still in flight")
	case <-time.After(200 * time.Millisecond):
	}

	certApplications.mu.Lock()
	_, stillRunning := certApplications.applications[onDemandTestDomain]
	certApplications.mu.Unlock()
	if !stillRunning {
		t.Fatal("shared application was torn down when the leader canceled")
	}
	if got := issuer.issueCalls.Load(); got != 1 {
		t.Fatalf("expected the single issuance to keep running, but issue calls = %d", got)
	}

	// Completing the issuance must still succeed for the surviving waiter, and
	// the detached leader goroutine then returns its own result without error.
	close(issuer.release)
	select {
	case err := <-waiterErr:
		if err != nil {
			t.Fatalf("surviving waiter should receive the cert, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("surviving waiter did not return after issuance completed")
	}
	select {
	case err := <-leaderErr:
		if err != nil {
			t.Fatalf("detached leader should complete the issuance, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not return after the detached issuance completed")
	}

	// Requirement (3): the certificate is published in the cache and storage.
	if certs := cfg.certCache.getAllMatchingCerts(onDemandTestDomain); len(certs) != 1 {
		t.Errorf("expected 1 cached certificate, got %d", len(certs))
	}
	if !cfg.storageHasCertResourcesAnyIssuer(context.Background(), onDemandTestDomain) {
		t.Error("certificate resources were not published to storage")
	}
}

// TestOnDemandWaiterCancellationIsLocal verifies requirement (2) from the
// waiter side: a canceling waiter returns immediately while the application
// (and every other waiter) keeps running.
func TestOnDemandWaiterCancellationIsLocal(t *testing.T) {
	resetCertApplications(t)
	issuer := newBlockingIssuer()
	cfg := newOnDemandTestConfig(t, issuer)

	leaderErr := make(chan error, 1)
	go func() {
		_, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
		leaderErr <- err
	}()
	<-issuer.started

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	waiterErr := make(chan error, 1)
	go func() {
		_, err := cfg.getCertDuringHandshake(waiterCtx, onDemandHello(onDemandTestDomain), true)
		waiterErr <- err
	}()
	time.Sleep(50 * time.Millisecond)

	cancelWaiter()
	select {
	case err := <-waiterErr:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("waiter expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not return after cancellation")
	}

	// The application and its single issuance survive the waiter's departure.
	certApplications.mu.Lock()
	_, stillRunning := certApplications.applications[onDemandTestDomain]
	certApplications.mu.Unlock()
	if !stillRunning {
		t.Fatal("shared application was canceled by a departing waiter")
	}

	close(issuer.release)
	select {
	case err := <-leaderErr:
		if err != nil {
			t.Fatalf("leader should still complete, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not complete after the waiter left")
	}
	if got := issuer.issueCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 issuance, got %d", got)
	}
}

// TestOnDemandFailureReleasesSlot verifies requirement (4): a failed
// application publishes no certificate, releases its slot, and the next
// explicit request starts a fresh application rather than inheriting the
// dead result.
func TestOnDemandFailureReleasesSlot(t *testing.T) {
	resetCertApplications(t)
	issuer := newBlockingIssuer()
	// ErrNoRetry stops doWithRetry from sleeping through retryIntervals, so
	// the failure is terminal and immediate.
	issuer.fail = ErrNoRetry{Err: errors.New("simulated CA rejection")}
	cfg := newOnDemandTestConfig(t, issuer)

	_, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
	if err == nil {
		t.Fatal("expected the failed obtain to return an error")
	}

	// Nothing was published.
	if certs := cfg.certCache.getAllMatchingCerts(onDemandTestDomain); len(certs) != 0 {
		t.Errorf("expected no cached certificate after failure, got %d", len(certs))
	}
	if cfg.storageHasCertResourcesAnyIssuer(context.Background(), onDemandTestDomain) {
		t.Error("expected no certificate resources in storage after failure")
	}

	// The slot was released...
	certApplications.mu.Lock()
	_, slotHeld := certApplications.applications[onDemandTestDomain]
	certApplications.mu.Unlock()
	if slotHeld {
		t.Fatal("failed application did not release its slot")
	}

	// ...and a subsequent explicit request starts a new application. Since
	// the issuer keeps failing, it must still be invoked again rather than
	// being suppressed by the previous attempt's terminal error.
	_, err = cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
	if err == nil {
		t.Fatal("expected the retry attempt to fail as well")
	}
	if got := issuer.issueCalls.Load(); got < 2 {
		t.Errorf("expected a fresh issuance attempt after failure, got %d calls", got)
	}
}

// TestOnDemandAllWaitersReadSameTerminalCert verifies requirement (3): once
// issuance succeeds, every waiter gets the same terminal certificate, and a
// later handshake for the canonical identity is served straight from the
// cache with no additional issuance.
func TestOnDemandAllWaitersReadSameTerminalCert(t *testing.T) {
	resetCertApplications(t)
	issuer := newBlockingIssuer()
	cfg := newOnDemandTestConfig(t, issuer)

	const waiters = 4
	certs := make(chan Certificate, waiters)
	errs := make(chan error, waiters)

	for i := 0; i < waiters; i++ {
		go func() {
			cert, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
			if err != nil {
				errs <- err
				return
			}
			certs <- cert
		}()
	}
	<-issuer.started
	time.Sleep(50 * time.Millisecond) // let the extra goroutines park as waiters

	close(issuer.release)

	var firstHash string
	for i := 0; i < waiters; i++ {
		select {
		case err := <-errs:
			t.Fatalf("waiter %d got error: %v", i, err)
		case cert := <-certs:
			if cert.Empty() {
				t.Fatalf("waiter %d got an empty certificate", i)
			}
			if firstHash == "" {
				firstHash = cert.hash
			} else if cert.hash != firstHash {
				t.Errorf("waiter %d got cert hash %s, want shared terminal hash %s", i, cert.hash, firstHash)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter %d did not return", i)
		}
	}

	// A fresh handshake now hits the cache directly; the issuer is not asked
	// again, proving all waiters observed the same published terminal state.
	cert, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
	if err != nil {
		t.Fatalf("post-completion handshake failed: %v", err)
	}
	if cert.hash != firstHash {
		t.Errorf("cache lookup returned hash %s, want %s", cert.hash, firstHash)
	}
	if got := issuer.issueCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 issuance, got %d", got)
	}
}

// TestOnDemandWaitersShareLeaderError verifies the state boundary on the
// failure path: when the leader is denied by the on-demand DecisionFunc, all
// queued waiters receive that same terminal error instead of each starting
// its own application, and the decision is evaluated exactly once.
func TestOnDemandWaitersShareLeaderError(t *testing.T) {
	resetCertApplications(t)

	var decisionCalls atomic.Int32
	denyErr := errors.New("on-demand permission denied")
	release := make(chan struct{})

	var cfg *Config
	cache := NewCache(CacheOptions{
		GetConfigForCert: func(Certificate) (*Config, error) { return cfg, nil },
		Logger:           zap.NewNop(),
	})
	t.Cleanup(cache.Stop)
	cfg = New(cache, Config{
		Storage: &FileStorage{Path: t.TempDir()},
		Logger:  zap.NewNop(),
		Issuers: []Issuer{newBlockingIssuer()},
		OnDemand: &OnDemandConfig{
			DecisionFunc: func(context.Context, string) error {
				decisionCalls.Add(1)
				<-release
				return denyErr
			},
		},
		OCSP: OCSPConfig{DisableStapling: true},
	})

	const waiters = 4
	errs := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			_, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
			errs <- err
		}()
	}

	if !waitUntil(time.Second, func() bool {
		certApplications.mu.Lock()
		_, ok := certApplications.applications[onDemandTestDomain]
		certApplications.mu.Unlock()
		return ok
	}) {
		t.Fatal("leader application was never registered")
	}
	time.Sleep(50 * time.Millisecond) // let the other goroutines park as waiters

	close(release)
	for i := 0; i < waiters; i++ {
		select {
		case err := <-errs:
			if err == nil || !errors.Is(err, denyErr) {
				t.Errorf("waiter %d expected deny error %v, got %v", i, denyErr, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("waiter %d did not return", i)
		}
	}

	if got := decisionCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 decision call, got %d", got)
	}
	certApplications.mu.Lock()
	_, slotHeld := certApplications.applications[onDemandTestDomain]
	certApplications.mu.Unlock()
	if slotHeld {
		t.Error("denied application did not release its slot")
	}
}

// TestOnDemandCacheLookupUsesCanonicalName verifies that once a certificate
// is cached, handshakes using case or trailing-dot variants of the same SNI
// match it without starting any new application.
func TestOnDemandCacheLookupUsesCanonicalName(t *testing.T) {
	resetCertApplications(t)
	issuer := newBlockingIssuer()
	cfg := newOnDemandTestConfig(t, issuer)

	done := make(chan error, 1)
	go func() {
		_, err := cfg.getCertDuringHandshake(context.Background(), onDemandHello(onDemandTestDomain), true)
		done <- err
	}()
	<-issuer.started
	close(issuer.release)
	if err := <-done; err != nil {
		t.Fatalf("initial obtain: %v", err)
	}

	for _, variant := range []string{"ONDEMAND.EXAMPLE", "OnDemand.Example.", "ondemand.example."} {
		cert, matched, _ := cfg.getCertificateFromCache(onDemandHello(variant))
		if !matched {
			t.Errorf("SNI variant %q did not match the cached certificate", variant)
			continue
		}
		if cert.Empty() {
			t.Errorf("SNI variant %q matched an empty certificate", variant)
		}
	}
	if got := issuer.issueCalls.Load(); got != 1 {
		t.Errorf("cache variants triggered extra issuances: %d", got)
	}
}
