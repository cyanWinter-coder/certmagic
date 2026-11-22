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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path"
	"sync"
	"testing"
	"time"
)

// controllableStorage is a FileStorage whose operations can be made to block
// or fail, so tests can deterministically interleave concurrent cache writes.
type controllableStorage struct {
	*FileStorage

	mu       sync.Mutex
	blocked  map[string]chan struct{} // key -> channel closed to release the block
	failNext map[string]bool          // key -> the next Store fails
}

func newControllableStorage(t *testing.T) *controllableStorage {
	t.Helper()
	return &controllableStorage{
		FileStorage: &FileStorage{Path: t.TempDir()},
		blocked:     make(map[string]chan struct{}),
		failNext:    make(map[string]bool),
	}
}

func (s *controllableStorage) block(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blocked[key]; !ok {
		s.blocked[key] = make(chan struct{})
	}
}

func (s *controllableStorage) release(key string) {
	s.mu.Lock()
	ch, ok := s.blocked[key]
	s.mu.Unlock()
	if ok {
		close(ch)
	}
}

// blockedWait blocks until the named gate is released. It is used inside read
// callbacks to park a refresh in the middle of its work.
func (s *controllableStorage) blockedWait(t *testing.T, key string) {
	t.Helper()
	s.mu.Lock()
	ch, ok := s.blocked[key]
	s.mu.Unlock()
	if !ok {
		return
	}
	<-ch
}

func (s *controllableStorage) failStore(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext[key] = true
}

func (s *controllableStorage) Store(ctx context.Context, key string, value []byte) error {
	s.mu.Lock()
	ch, block := s.blocked[key]
	if s.failNext[key] {
		s.failNext[key] = false
		s.mu.Unlock()
		return errors.New("simulated storage failure")
	}
	s.mu.Unlock()
	if block {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.FileStorage.Store(ctx, key, value)
}

func newTestGenerationCache(t *testing.T) (*generationCache, *controllableStorage) {
	t.Helper()
	backend := newControllableStorage(t)
	return newGenerationCache(backend, defaultTestLogger), backend
}

func siteKeys(t *testing.T, issuerKey, domain string) []keyValue {
	t.Helper()
	return []keyValue{
		{key: StorageKeys.SitePrivateKey(issuerKey, domain), value: []byte("key-v1")},
		{key: StorageKeys.SiteCert(issuerKey, domain), value: []byte("cert-v1")},
		{key: StorageKeys.SiteMeta(issuerKey, domain), value: []byte("meta-v1")},
	}
}

// TestGenerationCacheStoreLoadRoundTrip: a stored batch is readable, all three
// files of the site share one group, and generation and identity are recorded.
func TestGenerationCacheStoreLoadRoundTrip(t *testing.T) {
	ctx := context.Background()
	gc, _ := newTestGenerationCache(t)
	const issuer, domain = "issuer-a", "example.com"
	batch := siteKeys(t, issuer, domain)

	if err := gc.StoreTx(ctx, batch); err != nil {
		t.Fatalf("StoreTx: %v", err)
	}

	for _, kv := range batch {
		got, err := gc.Load(ctx, kv.key)
		if err != nil {
			t.Fatalf("Load %s: %v", kv.key, err)
		}
		if !bytes.Equal(got, kv.value) {
			t.Errorf("Load %s: got %q, want %q", kv.key, got, kv.value)
		}
	}

	gc.mu.Lock()
	group := localCacheGroup(batch[0].key)
	gen := gc.entries[batch[0].key].Gen
	allSameGroup := true
	for _, kv := range batch {
		entry := gc.entries[kv.key]
		if entry.Group != group || entry.Gen != gen {
			allSameGroup = false
		}
	}
	gc.mu.Unlock()
	if !allSameGroup {
		t.Error("expected all site files to share a group and a generation")
	}
	if gen != 1 {
		t.Errorf("expected first generation to be 1, got %d", gen)
	}
}

// TestGenerationCacheGroupsArePerSite: different domains get independent
// coordination groups, and work on one never blocks the other (requirement 3).
func TestGenerationCacheGroupsArePerSite(t *testing.T) {
	const issuer = "issuer-a"
	g1 := localCacheGroup(StorageKeys.SiteCert(issuer, "one.example.com"))
	g2 := localCacheGroup(StorageKeys.SiteCert(issuer, "two.example.com"))
	if g1 == g2 {
		t.Fatalf("different sites must not share a group: %q", g1)
	}

	// all files of the same site share the site directory
	certKey := StorageKeys.SiteCert(issuer, "one.example.com")
	keyKey := StorageKeys.SitePrivateKey(issuer, "one.example.com")
	metaKey := StorageKeys.SiteMeta(issuer, "one.example.com")
	siteDir := StorageKeys.CertsSitePrefix(issuer, "one.example.com")
	for _, k := range []string{certKey, keyKey, metaKey, siteDir} {
		if localCacheGroup(k) != g1 {
			t.Errorf("%q grouped as %q, want %q", k, localCacheGroup(k), g1)
		}
	}

	// OCSP staples stand alone
	if localCacheGroup(path.Join(prefixOCSP, "staple.der")) != path.Join(prefixOCSP, "staple.der") {
		t.Error("OCSP staple should coordinate only with itself")
	}

	// a blocked write on one site must not delay a load on another
	ctx := context.Background()
	gc, backend := newTestGenerationCache(t)
	blockedKey := StorageKeys.SiteCert(issuer, "one.example.com")
	backend.block(blockedKey)
	done := make(chan error, 1)
	go func() {
		done <- gc.Store(ctx, blockedKey, []byte("blocked"))
	}()

	otherKey := StorageKeys.SiteCert(issuer, "two.example.com")
	if err := gc.Store(ctx, otherKey, []byte("independent")); err != nil {
		t.Fatalf("storing on another site: %v", err)
	}
	got, err := gc.Load(ctx, otherKey)
	if err != nil || string(got) != "independent" {
		t.Fatalf("other site was blocked by the stalled write: %v %q", err, got)
	}

	backend.release(blockedKey)
	if err := <-done; err != nil {
		t.Fatalf("blocked write finished with error: %v", err)
	}
}

// TestGenerationCacheStaleWriteLoses is the core fencing guarantee
// (requirement 1): a write based on an old generation is discarded when a newer
// generation has already committed, even though the stale content is produced
// afterwards. StoreIfNewer carries the generation the writer observed before
// doing its work, so a late-arriving old write cannot overwrite the new one.
func TestGenerationCacheStaleWriteLoses(t *testing.T) {
	ctx := context.Background()
	gc, backend := newTestGenerationCache(t)
	const key = "certificates/issuer-a/example.com/example.com.crt"

	// version 1 is committed at generation 1
	if err := gc.Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("seed v1: %v", err)
	}
	observedAtV1 := gc.observedGeneration(key)

	// another path renews and commits version 2 before the old writer finishes
	if err := gc.Store(ctx, key, []byte("new-v2")); err != nil {
		t.Fatalf("store v2: %v", err)
	}

	// the old writer now arrives carrying the generation it observed (v1); the
	// compare-and-set must reject it and leave the new version in place
	err := gc.StoreIfNewer(ctx,
		map[string]uint64{key: observedAtV1},
		[]keyValue{{key: key, value: []byte("stale-v1")}})
	if !errors.Is(err, errStaleGeneration) {
		t.Fatalf("stale write: %v, want errStaleGeneration", err)
	}
	got, err := gc.Load(ctx, key)
	if err != nil || string(got) != "new-v2" {
		t.Fatalf("new version was not preserved: %q, %v", got, err)
	}

	// the rejected write never landed its bytes either: the raw backend content
	// must still be the new version
	raw, err := backend.Load(ctx, key)
	if err != nil || string(raw) != "new-v2" {
		t.Fatalf("backend content changed despite rejected write: %q, %v", raw, err)
	}

	// a write based on the current observation commits normally
	current := gc.observedGeneration(key)
	if err := gc.StoreIfNewer(ctx,
		map[string]uint64{key: current},
		[]keyValue{{key: key, value: []byte("v3")}}); err != nil {
		t.Fatalf("current write should commit: %v", err)
	}
	got, err = gc.Load(ctx, key)
	if err != nil || string(got) != "v3" {
		t.Fatalf("current write did not commit: %q, %v", got, err)
	}
}

// TestGenerationCacheLateArrivingWriteAfterRenewal drives the full
// localCacheStorage path: a slow read-through on one instance observes the old
// generation, then a renewal commits a newer one on another instance; when the
// slow read finally tries to cache its stale bytes, the compare-and-set drops
// them rather than overwriting the new certificate.
func TestGenerationCacheLateArrivingWriteAfterRenewal(t *testing.T) {
	ctx := context.Background()
	backend := newControllableStorage(t)
	slow := newGenerationCache(backend, defaultTestLogger)
	fast := newGenerationCache(backend, defaultTestLogger)
	const key = "certificates/issuer-a/example.com/example.com.crt"

	// both instances serve version 1
	if err := slow.Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("seed v1: %v", err)
	}
	if _, err := fast.Load(ctx, key); err != nil {
		t.Fatalf("fast reads v1: %v", err)
	}

	// the slow instance's read stalls after observing the old generation.
	// Refresh holds only its own coordinator's group lock; the two coordinators
	// synchronize through the shared manifest, not through each other's mutex.
	backend.block("authoritative-read")
	slowDone := make(chan error, 1)
	go func() {
		_, err := slow.Refresh(ctx, key, func() ([]byte, error) {
			backend.blockedWait(t, "authoritative-read")
			return []byte("stale-v1"), nil
		})
		slowDone <- err
	}()
	time.Sleep(50 * time.Millisecond)

	// meanwhile the fast instance renews and commits the new certificate
	if err := fast.Store(ctx, key, []byte("new-v2")); err != nil {
		t.Fatalf("fast renewal: %v", err)
	}

	// release the slow read; its compare-and-set must now lose
	backend.release("authoritative-read")
	if err := <-slowDone; err != nil {
		t.Fatalf("slow refresh returned error: %v", err)
	}
	got, err := slow.Load(ctx, key)
	if err != nil || string(got) != "new-v2" {
		t.Fatalf("late stale refresh overwrote the new version: %q, %v", got, err)
	}
}

// TestGenerationCacheConcurrentWritesOnlyNewestSurvives hammers one key from
// many goroutines; every committed write must carry a valid identity and the
// final content must be one of the written values, never a torn mix.
func TestGenerationCacheConcurrentWritesOnlyNewestSurvives(t *testing.T) {
	ctx := context.Background()
	gc, _ := newTestGenerationCache(t)
	const key = "certificates/issuer-a/example.com/example.com.crt"

	const writers = 32
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := []byte{byte(i)}
			if err := gc.Store(ctx, key, value); err != nil && !errors.Is(err, errStaleGeneration) {
				t.Errorf("writer %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	got, err := gc.Load(ctx, key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 1 || got[0] >= writers {
		t.Fatalf("content is not any single written value: %v", got)
	}

	// the manifest must agree exactly with what is readable
	gc.mu.Lock()
	entry := gc.entries[key]
	gc.mu.Unlock()
	if entry.Hash != localContentHash(got) {
		t.Error("index identity does not match readable content")
	}
}

// TestGenerationCacheDeleteTombstonesFirst: invalidation commits the index
// before recycling content, and afterwards the key reads as absent
// (requirement 2).
func TestGenerationCacheDeleteTombstonesFirst(t *testing.T) {
	ctx := context.Background()
	gc, _ := newTestGenerationCache(t)
	const issuer, domain = "issuer-a", "example.com"
	batch := siteKeys(t, issuer, domain)
	if err := gc.StoreTx(ctx, batch); err != nil {
		t.Fatalf("StoreTx: %v", err)
	}

	siteDir := StorageKeys.CertsSitePrefix(issuer, domain)
	if err := gc.Delete(ctx, siteDir); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	for _, kv := range batch {
		if _, err := gc.Load(ctx, kv.key); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("Load %s after delete: %v, want ErrNotExist", kv.key, err)
		}
		// the underlying bytes are recycled too
		if gc.backend.Exists(ctx, kv.key) {
			t.Errorf("content of %s was not recycled", kv.key)
		}
	}

	// generations keep advancing across the tombstone, so a later write wins
	if err := gc.Store(ctx, batch[0].key, []byte("after-delete")); err != nil {
		t.Fatalf("Store after delete: %v", err)
	}
	got, err := gc.Load(ctx, batch[0].key)
	if err != nil || string(got) != "after-delete" {
		t.Fatalf("Load after re-store: %q, %v", got, err)
	}
}

// TestGenerationCacheStoreFailureKeepsOldVersion (requirement 4): a failed
// backend write leaves the previously committed version readable and returns
// the original error; a restart reloads the same persisted index.
func TestGenerationCacheStoreFailureKeepsOldVersion(t *testing.T) {
	ctx := context.Background()
	gc, backend := newTestGenerationCache(t)
	const key = "certificates/issuer-a/example.com/example.com.crt"

	if err := gc.Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("seed v1: %v", err)
	}

	backend.failStore(key)
	err := gc.Store(ctx, key, []byte("v2"))
	if err == nil {
		t.Fatal("expected the storage error to be returned, got nil")
	}

	got, loadErr := gc.Load(ctx, key)
	if loadErr != nil || string(got) != "v1" {
		t.Fatalf("old version not preserved after failure: %q, %v", got, loadErr)
	}

	// simulate a restart: a fresh coordinator over the same backend reloads
	// the persisted manifest and still serves v1
	restarted := newGenerationCache(backend, defaultTestLogger)
	got, err = restarted.Load(ctx, key)
	if err != nil || string(got) != "v1" {
		t.Fatalf("after restart: %q, %v", got, err)
	}
}

// TestGenerationCacheManifestFailureRollsBack: when the manifest cannot be
// committed, the in-memory index rolls back and orphaned content is recycled,
// so the old version remains the only readable one.
func TestGenerationCacheManifestFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	backend := newControllableStorage(t)
	gc := newGenerationCache(backend, defaultTestLogger)
	const key = "certificates/issuer-a/example.com/example.com.crt"

	if err := gc.Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("seed v1: %v", err)
	}

	backend.failStore(localCacheManifestKey)
	if err := gc.Store(ctx, key, []byte("v2")); err == nil {
		t.Fatal("expected a manifest failure error")
	}

	got, err := gc.Load(ctx, key)
	if err != nil || string(got) != "v1" {
		t.Fatalf("old version lost after manifest failure: %q, %v", got, err)
	}
}

// TestGenerationCacheOrphanedContentIsInvisible: bytes on disk without a
// matching index entry can never be served, which is what makes an interrupted
// multi-file write indistinguishable from a cache miss.
func TestGenerationCacheOrphanedContentIsInvisible(t *testing.T) {
	ctx := context.Background()
	gc, backend := newTestGenerationCache(t)
	const key = "certificates/issuer-a/example.com/example.com.crt"

	if err := backend.Store(ctx, key, []byte("orphan")); err != nil {
		t.Fatalf("write orphan: %v", err)
	}
	if _, err := gc.Load(ctx, key); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("orphaned content should be a miss, got %v", err)
	}

	// content whose bytes no longer match the index is likewise a miss
	if err := gc.Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := backend.Store(ctx, key, []byte("tampered")); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if _, err := gc.Load(ctx, key); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("tampered content should be a miss, got %v", err)
	}
}

// TestGenerationCacheRestartMonotonicGenerations: fencing tokens continue the
// persisted sequence after a restart, so an old writer cannot come back to life.
func TestGenerationCacheRestartMonotonicGenerations(t *testing.T) {
	ctx := context.Background()
	backend := newControllableStorage(t)
	gc := newGenerationCache(backend, defaultTestLogger)
	const key = "certificates/issuer-a/example.com/example.com.crt"

	if err := gc.Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("v1: %v", err)
	}
	if err := gc.Store(ctx, key, []byte("v2")); err != nil {
		t.Fatalf("v2: %v", err)
	}

	restarted := newGenerationCache(backend, defaultTestLogger)
	if err := restarted.Store(ctx, key, []byte("v3")); err != nil {
		t.Fatalf("v3 after restart: %v", err)
	}
	restarted.mu.Lock()
	gen := restarted.entries[key].Gen
	restarted.mu.Unlock()
	if gen != 3 {
		t.Errorf("expected generation 3 after restart, got %d", gen)
	}
}

// TestLocalCacheBatchTxAtomicSiteFiles verifies the end-to-end path used by
// saveCertResource: the certificate, private key, and metadata of one site are
// committed under one generation, so a reader can never see part of one
// version and part of another (requirements 1 and 2).
func TestLocalCacheBatchTxAtomicSiteFiles(t *testing.T) {
	ctx := context.Background()
	cfg, am, _, localCache := testLocalCacheConfig(t)
	cfg.LocalCache = localCache
	const domain = "example.com"

	v1 := testIssuedCertResource(t, am, domain, time.Now().Add(-60*24*time.Hour))
	v2 := testIssuedCertResource(t, am, domain, time.Now())

	save := func(res CertificateResource) error {
		metaBytes, err := json.MarshalIndent(res, "", "\t")
		if err != nil {
			return err
		}
		issuerKey := am.IssuerKey()
		tx, ok := cfg.groundTruthStorage().(txStorage)
		if !ok {
			t.Fatalf("ground truth storage does not support StoreTx")
		}
		return tx.StoreTx(ctx, []keyValue{
			{key: StorageKeys.SitePrivateKey(issuerKey, domain), value: res.PrivateKeyPEM},
			{key: StorageKeys.SiteCert(issuerKey, domain), value: res.CertificatePEM},
			{key: StorageKeys.SiteMeta(issuerKey, domain), value: metaBytes},
		})
	}

	if err := save(v1); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if err := save(v2); err != nil {
		t.Fatalf("save v2: %v", err)
	}

	// all three files must carry the same, latest generation
	lc := cfg.localGenerationCache()
	lc.mu.Lock()
	var gen uint64
	for _, key := range []string{
		StorageKeys.SitePrivateKey(am.IssuerKey(), domain),
		StorageKeys.SiteCert(am.IssuerKey(), domain),
		StorageKeys.SiteMeta(am.IssuerKey(), domain),
	} {
		entry, ok := lc.entries[key]
		if !ok {
			t.Fatalf("missing index entry for %s", key)
		}
		if gen == 0 {
			gen = entry.Gen
		} else if entry.Gen != gen {
			t.Errorf("site files committed under different generations: %d vs %d", entry.Gen, gen)
		}
	}
	lc.mu.Unlock()

	// and the readable bytes are all from v2
	cert, err := localCache.Load(ctx, StorageKeys.SiteCert(am.IssuerKey(), domain))
	if err != nil || !bytes.Equal(cert, v2.CertificatePEM) {
		t.Errorf("cached certificate is not v2: %v", err)
	}
	key, err := localCache.Load(ctx, StorageKeys.SitePrivateKey(am.IssuerKey(), domain))
	if err != nil || !bytes.Equal(key, v2.PrivateKeyPEM) {
		t.Errorf("cached private key is not v2: %v", err)
	}
}

// TestLocalCacheStoreFailureKeepsOldCache is requirement 4 at the wrapper
// level: when the authoritative Storage rejects a write, the local cache keeps
// the previous version and the original error is returned.
func TestLocalCacheStoreFailureKeepsOldCache(t *testing.T) {
	ctx := context.Background()
	cfg, _, _, localCache := testLocalCacheConfig(t)
	cfg.LocalCache = localCache
	const key = "certificates/issuer-a/example.com/example.com.crt"

	// seed v1 through a healthy storage
	if err := cfg.groundTruthStorage().Store(ctx, key, []byte("v1")); err != nil {
		t.Fatalf("seed v1: %v", err)
	}

	// make the authoritative storage fail the next write, then build a wrapper
	// that embeds the failing storage
	failing := &failingStorage{Storage: cfg.Storage, failStore: true}
	cfg.Storage = failing
	wrapper := cfg.groundTruthStorage()
	err := wrapper.Store(ctx, key, []byte("v2"))
	if err == nil {
		t.Fatal("expected the storage failure to be returned verbatim")
	}
	if !failing.errMessage(err) {
		t.Fatalf("error was not the original storage error: %v", err)
	}

	got, err := localCache.Load(ctx, key)
	if err != nil || string(got) != "v1" {
		t.Fatalf("old cache not preserved after storage failure: %q, %v", got, err)
	}
}

// failingStorage wraps a Storage and optionally fails Store calls, recording
// the sentinel so tests can assert the original error propagated.
type failingStorage struct {
	Storage
	failStore bool
}

var errSimulatedStoreFailure = errors.New("simulated authoritative store failure")

func (f *failingStorage) Store(ctx context.Context, key string, value []byte) error {
	if f.failStore {
		return errSimulatedStoreFailure
	}
	return f.Storage.Store(ctx, key, value)
}

func (f *failingStorage) errMessage(err error) bool {
	return errors.Is(err, errSimulatedStoreFailure) || err.Error() == errSimulatedStoreFailure.Error()
}
