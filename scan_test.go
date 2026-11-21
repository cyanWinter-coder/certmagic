package certmagic

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// seedStoredCert writes a self-signed certificate for domain to storage
// under issuerKey, in the standard CertMagic layout, and returns the
// certificate's storage key and PEM bytes.
func seedStoredCert(t *testing.T, storage Storage, issuerKey, domain string, notAfter time.Time) (string, []byte) {
	t.Helper()

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	_, _, certPEM := mustIssueTestCertificate(t, tmpl, nil, nil)

	certKey := StorageKeys.SiteCert(issuerKey, domain)
	if err := storage.Store(context.Background(), certKey, certPEM); err != nil {
		t.Fatalf("seeding certificate for %s: %v", domain, err)
	}
	return certKey, certPEM
}

// collectScan runs ScanStoredCertificates and gathers the yielded entries.
func collectScan(ctx context.Context, storage Storage, opts CertScanOptions) ([]ScannedCertificate, error) {
	var entries []ScannedCertificate
	err := ScanStoredCertificates(ctx, storage, opts, func(scanned ScannedCertificate) error {
		entries = append(entries, scanned)
		return nil
	})
	return entries, err
}

func scannedDomains(entries []ScannedCertificate) []string {
	var domains []string
	for _, entry := range entries {
		domains = append(domains, entry.Certificate.Subject.CommonName)
	}
	sort.Strings(domains)
	return domains
}

// TestScanStoredCertificatesPaginationBoundaries verifies that scanning
// with different page sizes visits every stored certificate exactly once:
// no duplicates and no omissions at page boundaries.
func TestScanStoredCertificatesPaginationBoundaries(t *testing.T) {
	storage := &FileStorage{Path: t.TempDir()}
	ctx := context.Background()

	const issuer1, issuer2 = "test_issuer_a", "test_issuer_b"
	var want []string
	for i := 0; i < 10; i++ {
		domain := fmt.Sprintf("site-%02d.example.com", i)
		issuer := issuer1
		if i%2 == 0 {
			issuer = issuer2
		}
		seedStoredCert(t, storage, issuer, domain, time.Now().Add(90*24*time.Hour))
		want = append(want, domain)
	}
	sort.Strings(want)

	for _, pageSize := range []int{1, 3, 4, 100} {
		t.Run(fmt.Sprintf("page_size_%d", pageSize), func(t *testing.T) {
			entries, err := collectScan(ctx, storage, CertScanOptions{
				PageSize: pageSize,
				Logger:   defaultTestLogger,
			})
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			got := scannedDomains(entries)
			if len(got) != len(want) {
				t.Fatalf("expected %d entries, got %d: %v", len(want), len(got), got)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("entry %d: expected %s, got %s (full result: %v)", i, want[i], got[i], got)
				}
			}
		})
	}
}

// TestScanStoredCertificatesConsistentView verifies that data created or
// modified after the scan started does not leak into the scan's results,
// and that each yielded entry carries the content from the scan's logical
// view (so it can be re-read without another storage load).
func TestScanStoredCertificatesConsistentView(t *testing.T) {
	storage := &FileStorage{Path: t.TempDir()}
	ctx := context.Background()

	const issuer = "test_issuer"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	_, pemA := seedStoredCert(t, storage, issuer, "a.example.com", notAfter)
	seedStoredCert(t, storage, issuer, "b.example.com", notAfter)
	seedStoredCert(t, storage, issuer, "c.example.com", notAfter)

	var entries []ScannedCertificate
	firstYield := true
	err := ScanStoredCertificates(ctx, storage, CertScanOptions{PageSize: 1, Logger: defaultTestLogger},
		func(scanned ScannedCertificate) error {
			entries = append(entries, scanned)
			if firstYield {
				firstYield = false
				// concurrent writer: create a brand-new site, and overwrite
				// a site the scan has not reached yet; neither may appear
				// in this scan's results
				seedStoredCert(t, storage, issuer, "d-new.example.com", notAfter)
				seedStoredCert(t, storage, issuer, "c.example.com", notAfter)
			}
			return nil
		})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	got := scannedDomains(entries)
	want := []string{"a.example.com", "b.example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected only pre-scan entries %v, got %v", want, got)
	}

	// each entry must be re-readable from the same logical view: the PEM
	// carried by the entry is what the scan observed, without re-loading
	for _, entry := range entries {
		if entry.Certificate == nil || len(entry.PEM) == 0 {
			t.Fatalf("entry %s is missing its in-view content", entry.CertKey)
		}
		if entry.Certificate.Subject.CommonName == "a.example.com" && string(entry.PEM) != string(pemA) {
			t.Fatal("entry PEM does not match the content stored before the scan")
		}
	}
}

// TestScanStoredCertificatesSkipsDeleted verifies that an entry deleted
// concurrently with the scan is never yielded, so maintenance cannot
// treat it as a valid certificate.
func TestScanStoredCertificatesSkipsDeleted(t *testing.T) {
	storage := &FileStorage{Path: t.TempDir()}
	ctx := context.Background()

	const issuer = "test_issuer"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	seedStoredCert(t, storage, issuer, "a.example.com", notAfter)
	seedStoredCert(t, storage, issuer, "b.example.com", notAfter)
	seedStoredCert(t, storage, issuer, "c.example.com", notAfter)

	var entries []ScannedCertificate
	firstYield := true
	err := ScanStoredCertificates(ctx, storage, CertScanOptions{PageSize: 1, Logger: defaultTestLogger},
		func(scanned ScannedCertificate) error {
			entries = append(entries, scanned)
			if firstYield {
				firstYield = false
				// concurrent deleter: remove a site the scan hasn't reached yet
				if err := storage.Delete(ctx, StorageKeys.CertsSitePrefix(issuer, "b.example.com")); err != nil {
					t.Errorf("deleting site concurrently: %v", err)
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	got := scannedDomains(entries)
	want := []string{"a.example.com", "c.example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected deleted entry to be skipped (%v), got %v", want, got)
	}
}

// TestScanStoredCertificatesSkipsCorrupt verifies that a corrupt entry is
// logged with its storage key and skipped, without failing the whole scan.
func TestScanStoredCertificatesSkipsCorrupt(t *testing.T) {
	storage := &FileStorage{Path: t.TempDir()}
	ctx := context.Background()

	const issuer = "test_issuer"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	seedStoredCert(t, storage, issuer, "good-1.example.com", notAfter)
	seedStoredCert(t, storage, issuer, "good-2.example.com", notAfter)

	// one corrupt entry: not PEM at all
	corruptKey := StorageKeys.SiteCert(issuer, "corrupt.example.com")
	if err := storage.Store(ctx, corruptKey, []byte("this is not a PEM certificate")); err != nil {
		t.Fatalf("seeding corrupt entry: %v", err)
	}
	// one corrupt entry: valid PEM envelope, but not a certificate inside
	badDERKey := StorageKeys.SiteCert(issuer, "bad-der.example.com")
	if err := storage.Store(ctx, badDERKey, []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n")); err != nil {
		t.Fatalf("seeding bad-DER entry: %v", err)
	}

	core, logs := observer.New(zap.WarnLevel)
	entries, err := collectScan(ctx, storage, CertScanOptions{
		PageSize: 2,
		Logger:   zap.New(core),
	})
	if err != nil {
		t.Fatalf("scan with corrupt entries should not fail, got: %v", err)
	}

	got := scannedDomains(entries)
	want := []string{"good-1.example.com", "good-2.example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected only valid entries %v, got %v", want, got)
	}

	// both corrupt entries must have been logged with their storage keys
	loggedKeys := make(map[string]bool)
	for _, logEntry := range logs.All() {
		for _, field := range logEntry.Context {
			if field.Key == "cert_key" {
				loggedKeys[field.String] = true
			}
		}
	}
	if !loggedKeys[corruptKey] {
		t.Errorf("corrupt entry %s was not logged", corruptKey)
	}
	if !loggedKeys[badDERKey] {
		t.Errorf("bad-DER entry %s was not logged", badDERKey)
	}
}

// countingStorage wraps a Storage and counts calls to its read methods,
// so tests can assert that a canceled scan stops touching storage.
type countingStorage struct {
	Storage
	mu    sync.Mutex
	calls int
}

func (cs *countingStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	cs.mu.Lock()
	cs.calls++
	cs.mu.Unlock()
	return cs.Storage.List(ctx, prefix, recursive)
}

func (cs *countingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	cs.mu.Lock()
	cs.calls++
	cs.mu.Unlock()
	return cs.Storage.Load(ctx, key)
}

func (cs *countingStorage) Stat(ctx context.Context, key string) (KeyInfo, error) {
	cs.mu.Lock()
	cs.calls++
	cs.mu.Unlock()
	return cs.Storage.Stat(ctx, key)
}

func (cs *countingStorage) count() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.calls
}

// TestScanStoredCertificatesCancellationStopsStorageAccess verifies that
// canceling the scan's context stops the scan promptly and that no further
// calls are made to the underlying storage afterwards.
func TestScanStoredCertificatesCancellationStopsStorageAccess(t *testing.T) {
	storage := &countingStorage{Storage: &FileStorage{Path: t.TempDir()}}

	const issuer = "test_issuer"
	notAfter := time.Now().Add(90 * 24 * time.Hour)
	for i := 0; i < 5; i++ {
		seedStoredCert(t, storage, issuer, fmt.Sprintf("site-%d.example.com", i), notAfter)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var callsAtCancel int
	yieldCount := 0
	err := ScanStoredCertificates(ctx, storage, CertScanOptions{PageSize: 2, Logger: defaultTestLogger},
		func(scanned ScannedCertificate) error {
			yieldCount++
			if yieldCount == 1 {
				cancel()
				callsAtCancel = storage.count()
			}
			return nil
		})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if yieldCount != 1 {
		t.Fatalf("expected scan to stop after cancellation, but yield was called %d times", yieldCount)
	}
	if got := storage.count(); got != callsAtCancel {
		t.Fatalf("storage was accessed %d more time(s) after cancellation", got-callsAtCancel)
	}
}

// TestScanStoredCertificatesEmptyStorage verifies that scanning storage
// with no certificates is a no-op rather than an error.
func TestScanStoredCertificatesEmptyStorage(t *testing.T) {
	storage := &FileStorage{Path: t.TempDir()}
	entries, err := collectScan(context.Background(), storage, CertScanOptions{Logger: defaultTestLogger})
	if err != nil {
		t.Fatalf("scan of empty storage failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(entries))
	}
}

// TestDeleteExpiredCertsWithCorruptAndConcurrentEntries verifies that the
// maintenance cleaning flow uses the bounded consistent scan: expired
// certificates are removed (all their assets, and the now-empty site
// folder), valid certificates are kept, and a corrupt entry neither aborts
// the cleaning nor gets treated as a valid certificate.
func TestDeleteExpiredCertsWithCorruptAndConcurrentEntries(t *testing.T) {
	storage := &FileStorage{Path: t.TempDir()}
	ctx := context.Background()

	const issuer = "test_issuer"

	// an expired certificate, with all its related assets
	expiredKey, expiredPEM := seedStoredCert(t, storage, issuer, "expired.example.com", time.Now().Add(-2*time.Hour))
	expiredSite := StorageKeys.CertsSitePrefix(issuer, "expired.example.com")
	baseName := expiredKey[:len(expiredKey)-len(".crt")]
	if err := storage.Store(ctx, baseName+".key", []byte("fake key")); err != nil {
		t.Fatalf("seeding private key: %v", err)
	}
	if err := storage.Store(ctx, baseName+".json", []byte("{}")); err != nil {
		t.Fatalf("seeding metadata: %v", err)
	}
	_ = expiredPEM

	// a still-valid certificate
	validKey, _ := seedStoredCert(t, storage, issuer, "valid.example.com", time.Now().Add(90*24*time.Hour))

	// a corrupt certificate file
	corruptKey := StorageKeys.SiteCert(issuer, "corrupt.example.com")
	if err := storage.Store(ctx, corruptKey, []byte("garbage")); err != nil {
		t.Fatalf("seeding corrupt entry: %v", err)
	}

	err := deleteExpiredCerts(ctx, storage, defaultTestLogger, time.Hour)
	if err != nil {
		t.Fatalf("deleteExpiredCerts failed (corrupt entry should not abort the batch): %v", err)
	}

	// expired certificate: all assets and the empty site folder are gone
	for _, key := range []string{expiredKey, baseName + ".key", baseName + ".json"} {
		if storage.Exists(ctx, key) {
			t.Errorf("expected expired asset %s to be deleted", key)
		}
	}
	if storage.Exists(ctx, expiredSite) {
		t.Error("expected emptied site folder to be deleted")
	}

	// valid certificate is untouched
	if !storage.Exists(ctx, validKey) {
		t.Error("valid certificate was wrongly deleted")
	}

	// corrupt entry is left in place (skipped, not published or deleted)
	if !storage.Exists(ctx, corruptKey) {
		t.Error("corrupt entry should have been skipped, not deleted")
	}
}
