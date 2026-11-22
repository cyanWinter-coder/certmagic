package certmagic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

const dummyCA = "https://example.com/acme/directory"

// fakeACMEServer is a minimal ACME server for testing issuance flows. It
// does not verify JWS signatures; it records which account (by "kid" from
// the JWS protected header) was used for each order, and individual
// endpoints can be programmed to fail.
type fakeACMEServer struct {
	srv *httptest.Server

	mu           sync.Mutex
	accounts     map[string]bool // account location → exists on the "server"
	orders       []fakeOrder     // one entry per new-order call, even rejected ones
	solved       map[int]bool    // order ID → challenge solved
	acctSeq      int
	newAcctCalls int

	failNewAccount atomic.Bool // new-account responds with an error
	failChallenge  atomic.Bool // challenge initiation responds with accountDoesNotExist

	nonceSeq atomic.Int64
}

type fakeOrder struct {
	accountLocation string // "kid" of the new-order request
	rejected        bool   // true if the order was rejected (account unknown)
}

func newFakeACMEServer(t *testing.T) *fakeACMEServer {
	t.Helper()
	f := &fakeACMEServer{
		accounts: make(map[string]bool),
		solved:   make(map[int]bool),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory", f.handleDirectory)
	mux.HandleFunc("HEAD /new-nonce", f.handleNonce)
	mux.HandleFunc("GET /new-nonce", f.handleNonce)
	mux.HandleFunc("POST /new-account", f.handleNewAccount)
	mux.HandleFunc("POST /new-order", f.handleNewOrder)
	mux.HandleFunc("POST /authz/{id}", f.handleAuthz)
	mux.HandleFunc("POST /chal/{id}", f.handleChallenge)
	mux.HandleFunc("POST /finalize/{id}", f.handleFinalize)
	mux.HandleFunc("POST /order/{id}", f.handleOrder)
	mux.HandleFunc("POST /cert/{id}", f.handleCert)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeACMEServer) directory() string { return f.srv.URL + "/directory" }

// newAccountCount returns how many accounts were successfully registered.
func (f *fakeACMEServer) newAccountCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newAcctCalls
}

// orderAccounts returns the account location of every new-order call, in
// order, including rejected ones.
func (f *fakeACMEServer) orderAccounts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, o := range f.orders {
		out = append(out, o.accountLocation)
	}
	return out
}

// deleteAccount simulates the CA losing an account (e.g. CA reset/reinstall).
func (f *fakeACMEServer) deleteAccount(location string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.accounts, location)
}

func (f *fakeACMEServer) nextNonce() string {
	return fmt.Sprintf("nonce-%d", f.nonceSeq.Add(1))
}

func (f *fakeACMEServer) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Replay-Nonce", f.nextNonce())
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeACMEServer) writeProblem(w http.ResponseWriter, status int, probType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Replay-Nonce", f.nextNonce())
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(acme.Problem{
		Type:   probType,
		Status: status,
		Detail: detail,
	})
}

func (f *fakeACMEServer) handleDirectory(w http.ResponseWriter, r *http.Request) {
	f.writeJSON(w, http.StatusOK, map[string]any{
		"newNonce":   f.srv.URL + "/new-nonce",
		"newAccount": f.srv.URL + "/new-account",
		"newOrder":   f.srv.URL + "/new-order",
	})
}

func (f *fakeACMEServer) handleNonce(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", f.nextNonce())
	w.WriteHeader(http.StatusOK)
}

func (f *fakeACMEServer) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	if f.failNewAccount.Load() {
		f.writeProblem(w, http.StatusForbidden, acme.ProblemTypeUnauthorized, "registration disabled")
		return
	}
	body, _ := io.ReadAll(r.Body)
	payload := decodeJWSPart(body, "payload")

	f.mu.Lock()
	f.acctSeq++
	f.newAcctCalls++
	location := fmt.Sprintf("%s/acct/%d", f.srv.URL, f.acctSeq)
	f.accounts[location] = true
	f.mu.Unlock()

	w.Header().Set("Location", location)
	f.writeJSON(w, http.StatusCreated, map[string]any{
		"status":  "valid",
		"contact": payload["contact"],
	})
}

func (f *fakeACMEServer) handleNewOrder(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	protected := decodeJWSPart(body, "protected")
	kid, _ := protected["kid"].(string)
	payload := decodeJWSPart(body, "payload")

	f.mu.Lock()
	if !f.accounts[kid] {
		f.orders = append(f.orders, fakeOrder{accountLocation: kid, rejected: true})
		f.mu.Unlock()
		f.writeProblem(w, http.StatusBadRequest, acme.ProblemTypeAccountDoesNotExist, "account does not exist")
		return
	}
	orderID := len(f.orders) + 1
	f.orders = append(f.orders, fakeOrder{accountLocation: kid})
	f.mu.Unlock()

	w.Header().Set("Location", fmt.Sprintf("%s/order/%d", f.srv.URL, orderID))
	f.writeJSON(w, http.StatusCreated, map[string]any{
		"status":      "pending",
		"expires":     time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"identifiers": payload["identifiers"],
		"authorizations": []string{
			fmt.Sprintf("%s/authz/%d", f.srv.URL, orderID),
		},
		"finalize": fmt.Sprintf("%s/finalize/%d", f.srv.URL, orderID),
	})
}

func (f *fakeACMEServer) handleAuthz(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	f.mu.Lock()
	solved := f.solved[id]
	f.mu.Unlock()

	status := "pending"
	if solved {
		status = "valid"
	}
	f.writeJSON(w, http.StatusOK, map[string]any{
		"status":     status,
		"identifier": map[string]string{"type": "dns", "value": "example.com"},
		"challenges": []map[string]any{{
			"type":   "dns-01",
			"status": status,
			"url":    fmt.Sprintf("%s/chal/%d", f.srv.URL, id),
			"token":  "test-token",
		}},
	})
}

func (f *fakeACMEServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	if f.failChallenge.Load() {
		// simulates the account disappearing in the middle of an order,
		// after a challenge has already been presented
		f.writeProblem(w, http.StatusBadRequest, acme.ProblemTypeAccountDoesNotExist, "account gone mid-order")
		return
	}
	id := pathID(r)
	f.mu.Lock()
	f.solved[id] = true
	f.mu.Unlock()
	f.writeJSON(w, http.StatusOK, map[string]any{
		"type":   "dns-01",
		"status": "valid",
		"url":    fmt.Sprintf("%s/chal/%d", f.srv.URL, id),
		"token":  "test-token",
	})
}

func (f *fakeACMEServer) handleFinalize(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	// the response is decoded into the client's existing order object, so
	// only the changed fields need to be sent
	w.Header().Set("Location", fmt.Sprintf("%s/order/%d", f.srv.URL, id))
	f.writeJSON(w, http.StatusOK, map[string]any{
		"status":      "valid",
		"certificate": fmt.Sprintf("%s/cert/%d", f.srv.URL, id),
	})
}

func (f *fakeACMEServer) handleOrder(w http.ResponseWriter, r *http.Request) {
	id := pathID(r)
	f.writeJSON(w, http.StatusOK, map[string]any{
		"status":      "valid",
		"certificate": fmt.Sprintf("%s/cert/%d", f.srv.URL, id),
	})
}

func (f *fakeACMEServer) handleCert(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Header().Set("Replay-Nonce", f.nextNonce())
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(fakeCertChainPEM)
}

// fakeCertChainPEM is not a real certificate, but issuance only needs the
// PEM bytes; nothing in the issuance path parses them.
var fakeCertChainPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake certificate")})

// pathID extracts the trailing integer ID of the request path.
func pathID(r *http.Request) int {
	var id int
	fmt.Sscanf(r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], "%d", &id)
	return id
}

// decodeJWSPart decodes one part ("protected" or "payload") of a flattened
// JSON JWS request body. Returns nil for empty payloads (POST-as-GET).
func decodeJWSPart(body []byte, part string) map[string]any {
	var jws map[string]string
	if err := json.Unmarshal(body, &jws); err != nil {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws[part])
	if err != nil || len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// testStorage is a thread-safe in-memory Storage implementation for tests.
type testStorage struct {
	mu    sync.RWMutex
	data  map[string][]byte
	locks map[string]*sync.Mutex
}

func newTestStorage() *testStorage {
	return &testStorage{
		data:  make(map[string][]byte),
		locks: make(map[string]*sync.Mutex),
	}
}

func (s *testStorage) Store(ctx context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *testStorage) Load(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return v, nil
}

func (s *testStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[key]; !ok {
		return fs.ErrNotExist
	}
	delete(s.data, key)
	return nil
}

func (s *testStorage) Exists(ctx context.Context, key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[key]
	return ok
}

func (s *testStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]bool)
	var out []string
	for key := range s.data {
		if !strings.HasPrefix(key, prefix+"/") {
			continue
		}
		name := strings.TrimPrefix(key, prefix+"/")
		if !recursive {
			if i := strings.Index(name, "/"); i >= 0 {
				name = name[:i]
			}
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out, nil
}

func (s *testStorage) Stat(ctx context.Context, key string) (KeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return KeyInfo{}, fs.ErrNotExist
	}
	return KeyInfo{Key: key, Size: int64(len(v)), IsTerminal: true}, nil
}

func (s *testStorage) Lock(ctx context.Context, name string) error {
	s.mu.Lock()
	l, ok := s.locks[name]
	if !ok {
		l = new(sync.Mutex)
		s.locks[name] = l
	}
	s.mu.Unlock()
	l.Lock()
	return nil
}

func (s *testStorage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.locks[name]
	if !ok {
		return fmt.Errorf("lock %s not held", name)
	}
	l.Unlock()
	return nil
}

var _ Storage = (*testStorage)(nil)

// noOpSolver is a Solver that presents and cleans up challenges without
// doing anything; the fake ACME server validates challenges unconditionally.
type noOpSolver struct{}

func (noOpSolver) Present(ctx context.Context, chal acme.Challenge) error { return nil }
func (noOpSolver) CleanUp(ctx context.Context, chal acme.Challenge) error { return nil }

// newTestACMEIssuer returns an ACMEIssuer backed by the fake CA and storage.
func newTestACMEIssuer(t *testing.T, caURL string, storage Storage) *ACMEIssuer {
	t.Helper()
	cfg := &Config{
		Storage:   storage,
		Logger:    defaultTestLogger,
		certCache: new(Cache),
	}
	am := NewACMEIssuer(cfg, ACMEIssuer{
		CA:          caURL,
		Email:       "test@example.com",
		Agreed:      true,
		DNS01Solver: noOpSolver{},
		Logger:      zap.NewNop(),
	})
	cfg.Issuers = []Issuer{am}
	return am
}

func testCSR(t *testing.T, names ...string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}
	return csr
}

// setupIssuedAccount creates a fake CA, issuer, and performs one successful
// issuance so that an account is registered and stored. It returns the
// issuer, the fake CA, and the account as stored after the first issuance.
func setupIssuedAccount(t *testing.T, ctx context.Context) (*ACMEIssuer, *fakeACMEServer, acme.Account) {
	t.Helper()
	ca := newFakeACMEServer(t)
	am := newTestACMEIssuer(t, ca.directory(), newTestStorage())
	if err := am.PreCheck(ctx, []string{"example.com"}, false); err != nil {
		t.Fatalf("PreCheck: %v", err)
	}
	if _, _, err := am.doIssue(ctx, testCSR(t, "example.com"), 0); err != nil {
		t.Fatalf("initial issuance: %v", err)
	}
	account, err := am.loadAccount(ctx, am.CA, am.getEmail())
	if err != nil {
		t.Fatalf("loading stored account: %v", err)
	}
	if ca.newAccountCount() != 1 {
		t.Fatalf("expected 1 registered account, got %d", ca.newAccountCount())
	}
	return am, ca, account
}

// TestDoIssueAccountRefreshUsesFreshSnapshot verifies that when the CA has
// forgotten our account, the issuance refreshes the account and retries
// with a fresh snapshot: the retried order uses the NEW account, and the
// stored account is replaced only after successful re-registration.
func TestDoIssueAccountRefreshUsesFreshSnapshot(t *testing.T) {
	ctx := context.Background()
	am, ca, oldAccount := setupIssuedAccount(t, ctx)

	// simulate the CA losing the account (e.g. CA reset/reinstall)
	ca.deleteAccount(oldAccount.Location)

	ic, _, err := am.doIssue(ctx, testCSR(t, "example.com"), 0)
	if err != nil {
		t.Fatalf("issuance after account loss: %v", err)
	}
	if ic == nil || len(ic.Certificate) == 0 {
		t.Fatal("expected a certificate")
	}

	// exactly one re-registration happened
	if got := ca.newAccountCount(); got != 2 {
		t.Errorf("expected 2 account registrations (initial + refresh), got %d", got)
	}

	// 3 orders: initial OK, rejected with stale account, OK with refreshed account
	orders := ca.orderAccounts()
	if len(orders) != 3 {
		t.Fatalf("expected 3 orders, got %d", len(orders))
	}
	if orders[1] != oldAccount.Location {
		t.Errorf("expected rejected order to use the stale account %s, got %s", oldAccount.Location, orders[1])
	}
	if orders[2] == oldAccount.Location {
		t.Error("retried order reused the stale account; expected the refreshed account")
	}

	// storage now holds the refreshed account, with a rotated key
	newAccount, err := am.loadAccount(ctx, am.CA, am.getEmail())
	if err != nil {
		t.Fatalf("loading refreshed account: %v", err)
	}
	if newAccount.Location == oldAccount.Location {
		t.Error("stored account location was not updated after refresh")
	}
	if accountKeysEqual(newAccount.PrivateKey, oldAccount.PrivateKey) {
		t.Error("expected account key rotation on refresh, but key is unchanged")
	}
}

// TestDoIssueAccountRefreshFailureKeepsLastValidAccount verifies that when
// the account refresh fails, the last valid account remains in storage and
// the issuance terminates immediately.
func TestDoIssueAccountRefreshFailureKeepsLastValidAccount(t *testing.T) {
	ctx := context.Background()
	am, ca, oldAccount := setupIssuedAccount(t, ctx)

	// the CA forgot our account, and re-registration is broken
	ca.deleteAccount(oldAccount.Location)
	ca.failNewAccount.Store(true)

	_, _, err := am.doIssue(ctx, testCSR(t, "example.com"), 0)
	if err == nil {
		t.Fatal("expected issuance to fail when account refresh fails")
	}

	// the last valid account is still in storage, untouched
	stored, err := am.loadAccount(ctx, am.CA, am.getEmail())
	if err != nil {
		t.Fatalf("last valid account was lost from storage: %v", err)
	}
	if stored.Location != oldAccount.Location {
		t.Errorf("stored account location changed: %s → %s", oldAccount.Location, stored.Location)
	}
	if !accountKeysEqual(stored.PrivateKey, oldAccount.PrivateKey) {
		t.Error("stored account key changed despite failed refresh")
	}

	// no new account was registered, and no order was placed with one
	if got := ca.newAccountCount(); got != 1 {
		t.Errorf("expected no additional registrations, got %d total", got)
	}
	if orders := ca.orderAccounts(); len(orders) != 2 {
		t.Errorf("expected 2 orders (initial + rejected), got %d", len(orders))
	}
}

// TestDoIssueNoReplayAfterChallengePresented verifies that an issuance
// attempt is not replayed once a challenge has been presented: the account
// is not refreshed mid-order and no new order is created.
func TestDoIssueNoReplayAfterChallengePresented(t *testing.T) {
	ctx := context.Background()
	am, ca, _ := setupIssuedAccount(t, ctx)

	// the account vanishes mid-order: challenge initiation fails with
	// accountDoesNotExist after the challenge was already presented
	ca.failChallenge.Store(true)

	_, _, err := am.doIssue(ctx, testCSR(t, "example.com"), 0)
	if err == nil {
		t.Fatal("expected issuance to fail")
	}

	// the attempt must NOT be replayed: no account refresh, no new order
	if got := ca.newAccountCount(); got != 1 {
		t.Errorf("account was refreshed even though a challenge had been presented (%d registrations)", got)
	}
	if orders := ca.orderAccounts(); len(orders) != 2 {
		t.Errorf("expected no retry order after presented challenge, got %d orders", len(orders))
	}
}

// TestConcurrentIssuanceIsolated verifies that concurrent issuances
// serialize only the account registration phase: the account is registered
// exactly once, every issuance gets its own client snapshot, and the
// certificate phase proceeds concurrently and independently.
func TestConcurrentIssuanceIsolated(t *testing.T) {
	ctx := context.Background()
	ca := newFakeACMEServer(t)
	am := newTestACMEIssuer(t, ca.directory(), newTestStorage())
	if err := am.PreCheck(ctx, []string{"example.com"}, false); err != nil {
		t.Fatalf("PreCheck: %v", err)
	}

	const n = 8

	// phase 1: concurrent client creation; registration must happen once
	var wg sync.WaitGroup
	clients := make([]*acmeClient, n)
	clientErrs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			clients[i], clientErrs[i] = am.newACMEClientWithAccount(ctx, false, false)
		}()
	}
	wg.Wait()

	if got := ca.newAccountCount(); got != 1 {
		t.Errorf("expected exactly 1 account registration, got %d", got)
	}
	seen := make(map[*acmeClient]bool)
	for i, c := range clients {
		if clientErrs[i] != nil {
			t.Fatalf("client %d: %v", i, clientErrs[i])
		}
		if seen[c] {
			t.Errorf("client %d: snapshot shared with another issuance", i)
		}
		seen[c] = true
		if c.account.Location != clients[0].account.Location {
			t.Errorf("client %d: different account location %s", i, c.account.Location)
		}
		if !c.canReplay() {
			t.Errorf("client %d: fresh snapshot should be replayable", i)
		}
	}

	// phase 2: concurrent issuances; the certificate phase is isolated
	certs := make([]*IssuedCertificate, n)
	issueErrs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			certs[i], _, issueErrs[i] = am.doIssue(ctx, testCSR(t, "example.com"), 0)
		}()
	}
	wg.Wait()

	for i := range n {
		if issueErrs[i] != nil {
			t.Errorf("issuance %d: %v", i, issueErrs[i])
		}
		if certs[i] == nil || len(certs[i].Certificate) == 0 {
			t.Errorf("issuance %d: no certificate", i)
		}
	}

	// still only one registration, and one order per issuance, all with
	// the same registered account
	if got := ca.newAccountCount(); got != 1 {
		t.Errorf("expected still 1 account registration, got %d", got)
	}
	orders := ca.orderAccounts()
	if len(orders) != n {
		t.Fatalf("expected %d orders, got %d", n, len(orders))
	}
	for i, loc := range orders {
		if loc != clients[0].account.Location {
			t.Errorf("order %d used account %s, expected %s", i, loc, clients[0].account.Location)
		}
	}
}
