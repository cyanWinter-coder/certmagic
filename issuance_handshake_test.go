// Copyright 2015 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certmagic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// swapOnDemandIssuances replaces the package-level on-demand issuance
// coordinator with a fresh, isolated queue for the duration of the test,
// so tests never observe each other's in-flight work or worker counts.
func swapOnDemandIssuances(t *testing.T) *issuanceQueue {
	t.Helper()
	fresh := newIssuanceQueue()
	old := onDemandIssuances
	onDemandIssuances = fresh
	t.Cleanup(func() { onDemandIssuances = old })
	return fresh
}

func testHello(t *testing.T, serverName string) *tls.ClientHelloInfo {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &tls.ClientHelloInfo{ServerName: serverName, Conn: conn}
}

// TestObtainOnDemandCertificateCoalescesAndSharesResult drives the real
// handshake entry point (obtainOnDemandCertificate) and verifies that
// concurrent, equivalently-spelled requests trigger exactly one
// issuance and all handshakes return the same certificate and result.
func TestObtainOnDemandCertificateCoalescesAndSharesResult(t *testing.T) {
	swapOnDemandIssuances(t)

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c, OnDemand: &OnDemandConfig{}}

	// Intercept the two lower-level operations the coordinated work
	// invokes, avoiding any real ACME/Storage interaction.
	var obtainCalls atomic.Int32
	var loadCalls atomic.Int32
	releaseObtain := make(chan struct{})

	cfg.obtainCertForTest = func(ctx context.Context, name string) error {
		obtainCalls.Add(1)
		<-releaseObtain
		return nil
	}
	leaf := &x509.Certificate{DNSNames: []string{"shared.example.com"}}
	cfg.loadCertForTest = func(ctx context.Context, name string) (Certificate, error) {
		loadCalls.Add(1)
		return Certificate{
			Names:       []string{name},
			Certificate: tls.Certificate{Leaf: leaf},
		}, nil
	}

	// Equivalent spellings: mixed case and a trailing dot must coalesce.
	hellos := []*tls.ClientHelloInfo{
		testHello(t, "shared.example.com"),
		testHello(t, "SHARED.Example.COM"),
		testHello(t, "shared.example.com."),
	}

	const n = 3
	var wg sync.WaitGroup
	type outcome struct {
		cert Certificate
		err  error
	}
	outcomes := make([]outcome, n)
	wg.Add(n)
	for i := range hellos {
		go func(i int) {
			defer wg.Done()
			cert, err := cfg.obtainOnDemandCertificate(context.Background(), hellos[i])
			outcomes[i] = outcome{cert, err}
		}(i)
	}

	// Wait until the single work item is registered and running before
	// releasing it, so all three callers are guaranteed to be attached.
	if !waitUntil(time.Second, func() bool {
		return onDemandIssuances.has(issuanceKey("shared.example.com"))
	}) {
		t.Fatal("work item never became visible in the coordinator")
	}
	close(releaseObtain)
	wg.Wait()

	for i, oc := range outcomes {
		if oc.err != nil {
			t.Errorf("handshake %d expected success, got: %v", i, oc.err)
		}
		if oc.cert.Leaf != leaf {
			t.Errorf("handshake %d did not receive the shared certificate", i)
		}
	}
	if got := obtainCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 issuance, got %d", got)
	}
	if got := loadCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 storage load, got %d", got)
	}
	if !waitUntil(time.Second, func() bool {
		return !onDemandIssuances.has(issuanceKey("shared.example.com"))
	}) {
		t.Fatal("coordinator retained the completed work item")
	}
}

// TestObtainOnDemandCertificateCancelDoesNotAbortSharedIssuance verifies
// requirement 2 end-to-end: a handshake whose client gives up returns an
// error to that caller only, while the shared issuance completes and a
// concurrent patient handshake still succeeds.
func TestObtainOnDemandCertificateCancelDoesNotAbortSharedIssuance(t *testing.T) {
	swapOnDemandIssuances(t)

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c, OnDemand: &OnDemandConfig{}}

	releaseObtain := make(chan struct{})
	var obtainSawCanceledCtx atomic.Bool
	cfg.obtainCertForTest = func(ctx context.Context, name string) error {
		<-releaseObtain
		if ctx.Err() != nil {
			obtainSawCanceledCtx.Store(true)
		}
		return nil
	}
	leaf := &x509.Certificate{DNSNames: []string{"cancel.example.com"}}
	cfg.loadCertForTest = func(ctx context.Context, name string) (Certificate, error) {
		return Certificate{
			Names:       []string{name},
			Certificate: tls.Certificate{Leaf: leaf},
		}, nil
	}

	// Impatient caller: cancels while the issuance is blocked.
	impatientCtx, cancel := context.WithCancel(context.Background())
	impatientErr := make(chan error, 1)
	go func() {
		_, err := cfg.obtainOnDemandCertificate(impatientCtx, testHello(t, "cancel.example.com"))
		impatientErr <- err
	}()

	if !waitUntil(time.Second, func() bool {
		return onDemandIssuances.has(issuanceKey("cancel.example.com"))
	}) {
		t.Fatal("work item never became visible")
	}

	// Patient caller attaches to the same work.
	patientDone := make(chan error, 1)
	go func() {
		_, err := cfg.obtainOnDemandCertificate(context.Background(), testHello(t, "cancel.example.com"))
		patientDone <- err
	}()

	cancel()
	select {
	case err := <-impatientErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("impatient caller expected context.Canceled, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("impatient caller did not return after canceling")
	}

	// The shared work must still be in flight after the cancellation.
	if !onDemandIssuances.has(issuanceKey("cancel.example.com")) {
		t.Fatal("shared issuance was aborted by one waiter's cancellation")
	}

	close(releaseObtain)
	select {
	case err := <-patientDone:
		if err != nil {
			t.Fatalf("patient caller expected success, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("patient caller never completed")
	}
	if obtainSawCanceledCtx.Load() {
		t.Fatal("the shared issuance observed a waiter's canceled context")
	}
}

// TestObtainOnDemandCertificateFailureIsRetryable verifies requirement 3:
// after a failed issuance, the work item is released and the next explicit
// request performs a fresh attempt that can succeed.
func TestObtainOnDemandCertificateFailureIsRetryable(t *testing.T) {
	swapOnDemandIssuances(t)

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c, OnDemand: &OnDemandConfig{}}

	boom := errors.New("issuance failed")
	var attempts atomic.Int32
	cfg.obtainCertForTest = func(ctx context.Context, name string) error {
		if attempts.Add(1) == 1 {
			return boom
		}
		return nil
	}
	leaf := &x509.Certificate{DNSNames: []string{"retry.example.com"}}
	cfg.loadCertForTest = func(ctx context.Context, name string) (Certificate, error) {
		return Certificate{
			Names:       []string{name},
			Certificate: tls.Certificate{Leaf: leaf},
		}, nil
	}

	if _, err := cfg.obtainOnDemandCertificate(context.Background(), testHello(t, "retry.example.com")); !errors.Is(err, boom) {
		t.Fatalf("first attempt expected %v, got: %v", boom, err)
	}
	if onDemandIssuances.has(issuanceKey("retry.example.com")) {
		t.Fatal("failed work item was not released; retry would be poisoned")
	}

	cert, err := cfg.obtainOnDemandCertificate(context.Background(), testHello(t, "retry.example.com"))
	if err != nil {
		t.Fatalf("retry attempt expected success, got: %v", err)
	}
	if cert.Leaf != leaf {
		t.Fatal("retry attempt did not return the issued certificate")
	}
	if got := attempts.Load(); got != 2 {
		t.Fatalf("expected 2 issuance attempts, got %d", got)
	}
}

// expiredTestCert builds a managed, expired certificate for the given
// name so the renewal path takes its blocking branch.
func expiredTestCert(name string) Certificate {
	return Certificate{
		Names:   []string{name},
		managed: true,
		Certificate: tls.Certificate{
			Leaf: &x509.Certificate{
				DNSNames:  []string{name},
				NotAfter:  time.Now().Add(-time.Hour),
				NotBefore: time.Now().Add(-2 * time.Hour),
			},
		},
	}
}

// TestRenewDynamicCertificateCoalescesAndSharesResult verifies that
// concurrent handshakes renewing an expired, equivalently-named cert run
// the renewal once and every blocking caller gets the renewed
// certificate.
func TestRenewDynamicCertificateCoalescesAndSharesResult(t *testing.T) {
	swapOnDemandIssuances(t)

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c, OnDemand: &OnDemandConfig{}}

	var renewCalls atomic.Int32
	release := make(chan struct{})
	var startOnce sync.Once
	started := make(chan struct{})
	cfg.renewCertForTest = func(ctx context.Context, name string) error {
		renewCalls.Add(1)
		startOnce.Do(func() { close(started) })
		<-release
		return nil
	}
	newLeaf := &x509.Certificate{DNSNames: []string{"renew.example.com"}, NotAfter: time.Now().Add(time.Hour)}
	cfg.reloadCertForTest = func(ctx context.Context, old Certificate) (Certificate, error) {
		return Certificate{
			Names:       old.Names,
			Certificate: tls.Certificate{Leaf: newLeaf},
		}, nil
	}

	current := expiredTestCert("renew.example.com")
	// Equivalent, certificate-eligible spellings must resolve to the same
	// work item. (Trailing-dot and Unicode equivalence is covered by the
	// issuanceKey unit tests; a trailing-dot SNI is itself rejected by
	// SubjectQualifiesForCert per RFC 6066.)
	hellos := []*tls.ClientHelloInfo{
		testHello(t, "renew.example.com"),
		testHello(t, "RENEW.Example.COM"),
		testHello(t, "Renew.Example.Com"),
	}

	const n = 3
	var wg sync.WaitGroup
	outcomes := make([]Certificate, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := range hellos {
		go func(i int) {
			defer wg.Done()
			outcomes[i], errs[i] = cfg.renewDynamicCertificate(context.Background(), hellos[i], current)
		}(i)
	}

	// Once the single run has started, the work item is live and every
	// caller blocks in work.wait. Wait until all n are registered as
	// waiters on that exact item before releasing it, which makes the
	// coalescing assertion scheduler-independent.
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("renewal work never started")
	}
	key := issuanceKey("renew.example.com")
	if !waitUntil(time.Second, func() bool {
		onDemandIssuances.mu.Lock()
		w := onDemandIssuances.inflight[key]
		onDemandIssuances.mu.Unlock()
		return w != nil && w.waiters.Load() == n
	}) {
		onDemandIssuances.mu.Lock()
		w := onDemandIssuances.inflight[key]
		var count int32
		if w != nil {
			count = w.waiters.Load()
		}
		onDemandIssuances.mu.Unlock()
		t.Fatalf("expected %d waiters coalesced on one work item, got %d", n, count)
	}
	close(release)
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("handshake %d expected successful renewal, got: %v", i, errs[i])
		}
		if outcomes[i].Leaf != newLeaf {
			t.Errorf("handshake %d did not receive the shared renewed certificate", i)
		}
	}
	if got := renewCalls.Load(); got != 1 {
		t.Errorf("expected exactly 1 renewal, got %d", got)
	}
}

// TestRenewDynamicCertificateCancelDoesNotAbortSharedRenewal verifies
// that one expiring-cert caller's canceled wait leaves the shared
// renewal running for a patient caller.
func TestRenewDynamicCertificateCancelDoesNotAbortSharedRenewal(t *testing.T) {
	swapOnDemandIssuances(t)

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c, OnDemand: &OnDemandConfig{}}

	release := make(chan struct{})
	var startOnce sync.Once
	started := make(chan struct{})
	var sawCanceledCtx atomic.Bool
	cfg.renewCertForTest = func(ctx context.Context, name string) error {
		startOnce.Do(func() { close(started) })
		<-release
		if ctx.Err() != nil {
			sawCanceledCtx.Store(true)
		}
		return nil
	}
	newLeaf := &x509.Certificate{DNSNames: []string{"rcancel.example.com"}, NotAfter: time.Now().Add(time.Hour)}
	cfg.reloadCertForTest = func(ctx context.Context, old Certificate) (Certificate, error) {
		return Certificate{Names: old.Names, Certificate: tls.Certificate{Leaf: newLeaf}}, nil
	}

	current := expiredTestCert("rcancel.example.com")

	impatientCtx, cancel := context.WithCancel(context.Background())
	impatientErr := make(chan error, 1)
	go func() {
		_, err := cfg.renewDynamicCertificate(impatientCtx, testHello(t, "rcancel.example.com"), current)
		impatientErr <- err
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("renewal work never started")
	}

	patientDone := make(chan Certificate, 1)
	patientErr := make(chan error, 1)
	go func() {
		cert, err := cfg.renewDynamicCertificate(context.Background(), testHello(t, "rcancel.example.com"), current)
		patientDone <- cert
		patientErr <- err
	}()

	cancel()
	select {
	case err := <-impatientErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("impatient renewal waiter expected context.Canceled, got: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("impatient renewal waiter did not return after cancel")
	}

	if !onDemandIssuances.has(issuanceKey("rcancel.example.com")) {
		t.Fatal("shared renewal was aborted by one waiter's cancellation")
	}

	close(release)
	select {
	case cert := <-patientDone:
		if err := <-patientErr; err != nil {
			t.Fatalf("patient renewal expected success, got: %v", err)
		}
		if cert.Leaf != newLeaf {
			t.Fatal("patient caller did not receive the renewed certificate")
		}
	case <-time.After(time.Second):
		t.Fatal("patient renewal never completed")
	}
	if sawCanceledCtx.Load() {
		t.Fatal("the shared renewal observed a waiter's canceled context")
	}
}

// TestRenewDynamicCertificateBackgroundForUnexpiredCert verifies that an
// unexpired certificate is returned immediately while its renewal runs in
// the background; the work item still exists and eventually settles.
func TestRenewDynamicCertificateBackgroundForUnexpiredCert(t *testing.T) {
	swapOnDemandIssuances(t)

	c := &Cache{
		cache:      make(map[string]Certificate),
		cacheIndex: make(map[string][]string),
		logger:     defaultTestLogger,
	}
	cfg := &Config{Logger: defaultTestLogger, certCache: c, OnDemand: &OnDemandConfig{}}

	release := make(chan struct{})
	var renewCalls atomic.Int32
	cfg.renewCertForTest = func(ctx context.Context, name string) error {
		renewCalls.Add(1)
		<-release
		return nil
	}
	cfg.reloadCertForTest = func(ctx context.Context, old Certificate) (Certificate, error) {
		return old, nil
	}

	current := Certificate{
		Names:   []string{"bg.example.com"},
		managed: true,
		Certificate: tls.Certificate{
			Leaf: &x509.Certificate{
				DNSNames:  []string{"bg.example.com"},
				NotBefore: time.Now().Add(-time.Hour),
				NotAfter:  time.Now().Add(time.Hour),
			},
		},
	}

	// Must return immediately with the current cert even though the
	// renewal is blocked.
	done := make(chan Certificate, 1)
	go func() {
		cert, err := cfg.renewDynamicCertificate(context.Background(), testHello(t, "bg.example.com"), current)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		done <- cert
	}()

	if !waitUntil(time.Second, func() bool {
		return onDemandIssuances.has(issuanceKey("bg.example.com"))
	}) {
		t.Fatal("background renewal was never queued")
	}

	select {
	case cert := <-done:
		if cert.Leaf != current.Leaf {
			t.Fatal("expected the still-valid current certificate to be served immediately")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake blocked instead of serving the unexpired cert")
	}

	close(release)
	if !waitUntil(time.Second, func() bool {
		return !onDemandIssuances.has(issuanceKey("bg.example.com"))
	}) {
		t.Fatal("background renewal work item leaked")
	}
	if got := renewCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 background renewal, got %d", got)
	}
}
