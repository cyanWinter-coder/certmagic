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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zeebo/blake3"
	"go.uber.org/zap"
)

// localCacheManifestKey is where a generationCache persists its index, inside
// the node-local storage it wraps. It lives next to the cached assets but is
// never served as one.
const localCacheManifestKey = "certmagic/local-cache-manifest.json"

// errStaleGeneration means a write carried a generation that lost the race
// against a newer one, so its content was deliberately discarded.
var errStaleGeneration = errors.New("stale local cache generation")

// localCacheEntry is the indexed state of a single key in a generationCache.
// The hash is the certificate (or other asset) identity: a reader only trusts
// content whose bytes still hash to what the index says. Gen is a fencing
// token, monotonically increasing within the entry's group.
type localCacheEntry struct {
	// Group is the coordination unit the entry belongs to. All files of one
	// certificate site share a group, so they advance through generations
	// together; OCSP staples and other lone files stand alone.
	Group string `json:"group"`

	// Hash identifies the content the entry points at.
	Hash string `json:"hash"`

	// Gen is the generation (fencing token) assigned to the write that last
	// changed this entry. Writes presenting an older generation are dropped.
	Gen uint64 `json:"gen"`

	// Deleted marks a tombstone: the key was invalidated and its content is
	// being (or has been) recycled. Tombstones are kept so generations keep
	// increasing across restarts.
	Deleted bool `json:"deleted,omitempty"`

	// Modified is when the entry last changed.
	Modified time.Time `json:"modified,omitempty"`
}

// localCacheManifest is the persisted index of a generationCache. It is the
// only source of truth for what is readable: content without a matching live
// entry is treated as absent, which makes a torn write indistinguishable from
// a cache miss and lets a later read repair it.
type localCacheManifest struct {
	Entries map[string]localCacheEntry `json:"entries"`
}

// generationCache wraps a node-local Storage with generation-based atomic
// replacement. Every write carries the asset identity (a content hash) and a
// monotonically increasing generation (fencing token) within its coordination
// group; a write whose generation arrives after a newer one committed is
// dropped. Invalidation, deletion, and reload update the persisted index first
// and only then recycle content, so a reader either sees the previous complete
// version or the new complete version, never a mixture.
//
// Coordination is per group: all operations on one certificate site share one
// mutex, while different sites (and other domains) never block each other.
//
// The cache remains an optimization: errors from it are meant to be logged by
// the caller so the authoritative Storage can answer the request.
type generationCache struct {
	backend Storage
	logger  *zap.Logger

	// mu protects entries and loaded; the manifest index is held in memory and
	// persisted through backend. Group locks never nest inside mu across I/O:
	// mu is only taken for short map updates and the single manifest write.
	mu      sync.Mutex
	entries map[string]localCacheEntry
	loaded  bool

	// groupLocks hands out the one mutex used by every Load, Store, and Delete
	// touching a given group. A mutex per group (rather than one for the whole
	// cache) is what keeps another domain's work unblocked.
	groupLocksMu sync.Mutex
	groupLocks   map[string]*sync.Mutex
}

// newGenerationCache returns a generation-coordinated cache in front of
// backend. Its index is loaded lazily on first use and after every restart.
func newGenerationCache(backend Storage, logger *zap.Logger) *generationCache {
	if logger == nil {
		logger = defaultLogger
	}
	return &generationCache{
		backend:    backend,
		logger:     logger,
		entries:    make(map[string]localCacheEntry),
		groupLocks: make(map[string]*sync.Mutex),
	}
}

// localCacheGroup maps a storage key to the coordination group it belongs to.
// The certificate, private key, and metadata of one site all share the site's
// directory as their group; directory keys for the site itself map to the same
// group, so deleting a site coordinates with writing its files. Everything
// else, notably OCSP staples, coordinates only with itself.
func localCacheGroup(key string) string {
	if !strings.HasPrefix(key, prefixCerts+"/") {
		return key
	}
	dir := path.Dir(key)
	// ".../<issuer>/<domain>" is a site directory: ".../<issuer>" has the
	// certs prefix as its parent, and the certs prefix itself is one level up.
	if dir == prefixCerts || path.Dir(dir) == prefixCerts {
		return key
	}
	return dir
}

// localContentHash is the asset identity recorded with every entry. It is not
// used for any cryptographic purpose.
func localContentHash(value []byte) string {
	h := blake3.New()
	h.Write(value)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ensureLoadedLocked reads the persisted index once. A missing manifest simply
// means an empty cache; a corrupt one is logged and reset, since the cache can
// repopulate itself from the authoritative Storage. Callers must hold mu.
func (gc *generationCache) ensureLoadedLocked() error {
	if gc.loaded {
		return nil
	}
	data, err := gc.backend.Load(context.Background(), localCacheManifestKey)
	if err == nil {
		var manifest localCacheManifest
		if jsonErr := json.Unmarshal(data, &manifest); jsonErr != nil {
			gc.logger.Warn("local cache manifest is unreadable; starting with an empty cache",
				zap.String("manifest", localCacheManifestKey),
				zap.Error(jsonErr))
		} else if manifest.Entries != nil {
			gc.entries = manifest.Entries
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	gc.loaded = true
	return nil
}

// reloadManifestLocked re-reads the persisted index so a coordinator can fence
// against generations another instance committed after its in-memory copy was
// populated. A missing or unreadable manifest leaves the current entries in
// place; the caller only uses the reloaded data for comparison. Callers must
// hold mu.
func (gc *generationCache) reloadManifestLocked() {
	data, err := gc.backend.Load(context.Background(), localCacheManifestKey)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			gc.logger.Debug("reloading local cache manifest; keeping in-memory index",
				zap.Error(err))
		}
		return
	}
	var manifest localCacheManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		gc.logger.Warn("reloaded local cache manifest is unreadable; keeping in-memory index",
			zap.Error(err))
		return
	}
	if manifest.Entries != nil {
		gc.entries = manifest.Entries
	}
}

// saveManifestLocked persists the current index. Callers must hold mu.
func (gc *generationCache) saveManifestLocked() error {
	manifest := localCacheManifest{Entries: gc.entries}
	data, err := json.MarshalIndent(manifest, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding local cache manifest: %w", err)
	}
	return gc.backend.Store(context.Background(), localCacheManifestKey, data)
}

// nextGenerationLocked returns the next fencing token for group. Tokens
// continue the sequence recorded in the manifest, so they stay monotonic
// across restarts. Callers must hold mu and the group lock.
func (gc *generationCache) nextGenerationLocked(group string) uint64 {
	var maxGen uint64
	for _, entry := range gc.entries {
		if entry.Group == group && entry.Gen > maxGen {
			maxGen = entry.Gen
		}
	}
	return maxGen + 1
}

// lockGroup returns the shared mutex for group.
func (gc *generationCache) lockGroup(group string) *sync.Mutex {
	gc.groupLocksMu.Lock()
	defer gc.groupLocksMu.Unlock()
	if l, ok := gc.groupLocks[group]; ok {
		return l
	}
	l := &sync.Mutex{}
	gc.groupLocks[group] = l
	return l
}

// lockGroups locks every group in groups, in a deterministic order so two
// batches spanning the same groups can never deadlock against each other.
func (gc *generationCache) lockGroups(groups []string) []*sync.Mutex {
	locks := make([]*sync.Mutex, 0, len(groups))
	for _, group := range groups {
		locks = append(locks, gc.lockGroup(group))
	}
	for _, l := range locks {
		l.Lock()
	}
	return locks
}

func unlockAll(locks []*sync.Mutex) {
	for i := len(locks) - 1; i >= 0; i-- {
		locks[i].Unlock()
	}
}

// groupsOf returns the distinct, sorted groups a batch touches.
func groupsOf(batch []keyValue) []string {
	seen := make(map[string]struct{})
	var groups []string
	for _, kv := range batch {
		group := localCacheGroup(kv.key)
		if _, ok := seen[group]; !ok {
			seen[group] = struct{}{}
			groups = append(groups, group)
		}
	}
	sort.Strings(groups)
	return groups
}

// Load returns the value at key only when the index has a live entry whose
// generation and identity still match the content on disk. Anything else is a
// cache miss (fs.ErrNotExist), including a tombstone or an orphaned file left
// by a write that never committed; the caller is expected to repair it from
// the authoritative Storage.
func (gc *generationCache) Load(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l := gc.lockGroup(localCacheGroup(key))
	l.Lock()
	defer l.Unlock()

	gc.mu.Lock()
	if err := gc.ensureLoadedLocked(); err != nil {
		gc.mu.Unlock()
		return nil, err
	}
	entry, ok := gc.entries[key]
	gc.mu.Unlock()
	if !ok || entry.Deleted {
		return nil, fs.ErrNotExist
	}

	value, err := gc.backend.Load(ctx, key)
	if err != nil {
		return nil, err
	}
	if localContentHash(value) != entry.Hash {
		gc.logger.Debug("local cache content does not match its index; treating as a miss",
			zap.String("key", key))
		return nil, fs.ErrNotExist
	}
	return value, nil
}

// Store stores a single value with a freshly issued generation.
func (gc *generationCache) Store(ctx context.Context, key string, value []byte) error {
	return gc.StoreTx(ctx, []keyValue{{key: key, value: value}})
}

// observedGeneration returns the generation the index currently records for
// key, or 0 if the key is absent/tombstoned. It is the value a caller passes
// back to StoreIfNewer to prove its write is based on a current observation.
func (gc *generationCache) observedGeneration(key string) uint64 {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	if err := gc.ensureLoadedLocked(); err != nil {
		return 0
	}
	gc.reloadManifestLocked()
	return gc.entries[key].Gen
}

// StoreIfNewer commits batch only while every touched key is still at
// observedGen (the generation the caller observed before doing its work). If
// a newer generation committed in the meantime -- the classic late-arriving
// old write -- the batch is dropped with errStaleGeneration and the newer
// version is left untouched. observedGen 0 means the caller expects the keys
// to be absent.
//
// The check and the commit happen under the group locks, so they are atomic
// relative to other writes on the same groups.
func (gc *generationCache) StoreIfNewer(ctx context.Context, observedGen map[string]uint64, batch []keyValue) error {
	if len(batch) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	locks := gc.lockGroups(groupsOf(batch))
	defer unlockAll(locks)
	return gc.commitIfNewer(ctx, observedGen, batch)
}

// StoreTx writes a batch as one coordinated change: all content is written
// before the index points at any of it, and the whole batch is dropped
// (errStaleGeneration) if another instance committed a newer generation first.
// Fencing tokens are derived inside the commit from the freshly reloaded
// manifest, so a coordinator with a stale in-memory view cannot overwrite a
// newer version. A failure leaves the previously committed version readable.
func (gc *generationCache) StoreTx(ctx context.Context, batch []keyValue) error {
	if len(batch) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	locks := gc.lockGroups(groupsOf(batch))
	defer unlockAll(locks)

	return gc.commitIndex(ctx, batch)
}

// Refresh reads key through read and caches the result, but only if no newer
// generation appeared while the read was in flight. The generation observed
// before the read is the compare-and-set token: if another write commits in
// the meantime, the read's value loses and is returned without being cached.
// The group lock is held across the read and commit so the check is atomic.
func (gc *generationCache) Refresh(ctx context.Context, key string, read func() ([]byte, error)) ([]byte, error) {
	l := gc.lockGroup(localCacheGroup(key))
	l.Lock()
	defer l.Unlock()

	observed := map[string]uint64{key: gc.observedGenerationLocked(key)}

	value, err := read()
	if err != nil {
		return nil, err
	}
	err = gc.commitIfNewer(ctx, observed, []keyValue{{key: key, value: value}})
	if err != nil {
		if errors.Is(err, errStaleGeneration) {
			// the read was valid when it happened, but a newer write has since
			// taken over the cache; serve what we read and leave the cache alone
			return value, nil
		}
		gc.logger.Warn("refreshing local cache entry",
			zap.String("key", key),
			zap.Error(err))
	}
	return value, nil
}

// observedGenerationLocked is observedGeneration for callers already holding
// the group lock; it reloads the manifest so the observation is current.
func (gc *generationCache) observedGenerationLocked(key string) uint64 {
	gc.mu.Lock()
	defer gc.mu.Unlock()
	if err := gc.ensureLoadedLocked(); err != nil {
		return 0
	}
	gc.reloadManifestLocked()
	return gc.entries[key].Gen
}

// commitIndex points the index at batch's content, writing content itself
// first so readers never follow the index to missing bytes. It reloads the
// persisted manifest and derives fencing tokens from it. On any failure the
// previous version stays readable: old content is backed up before being
// replaced and restored on rollback.
//
// When observedGen is non-nil, the commit becomes a compare-and-set: each key
// must still be at the generation the caller observed before doing its work,
// otherwise errStaleGeneration is returned and the newer committed version is
// left untouched. This is the late-arriving-write guard.
//
// The global mutex is held only for short map and manifest operations; all
// backend I/O happens while holding the group locks but not the global mutex,
// so a slow write for one domain never blocks another domain.
// Callers must already hold the group locks.
func (gc *generationCache) commitIndex(ctx context.Context, batch []keyValue) error {
	return gc.commitIfNewer(ctx, nil, batch)
}

// commitIfNewer is the compare-and-set core of commitIndex and StoreIfNewer.
func (gc *generationCache) commitIfNewer(ctx context.Context, observedGen map[string]uint64, batch []keyValue) error {
	gc.mu.Lock()
	if err := gc.ensureLoadedLocked(); err != nil {
		gc.mu.Unlock()
		return err
	}
	// re-read what other instances may have committed since our in-memory
	// index was populated, and derive the next fencing token from that
	gc.reloadManifestLocked()
	groups := groupsOf(batch)
	tickets := make(map[string]uint64, len(groups))
	for _, group := range groups {
		tickets[group] = gc.nextGenerationLocked(group)
	}
	for _, kv := range batch {
		if observedGen != nil {
			// compare-and-set: the key must still be at what the caller saw
			entry, exists := gc.entries[kv.key]
			want, saw := observedGen[kv.key], uint64(0)
			if exists {
				saw = entry.Gen
			}
			if saw != want {
				gc.logger.Debug("discarding stale local cache write",
					zap.String("key", kv.key),
					zap.Uint64("observed_gen", want),
					zap.Uint64("current_gen", saw))
				gc.mu.Unlock()
				return errStaleGeneration
			}
		}
	}
	snapshot := gc.snapshotEntries(batch)
	gc.mu.Unlock()

	// back up the currently readable content so a failed commit can restore it
	// instead of deleting the file and leaving nothing to serve
	backups, backupErr := gc.backupContent(ctx, batch)

	// 1. content first: a reader only follows an entry once its bytes are
	// durably in place (each backend Store is itself atomic). The group locks
	// keep same-group readers from racing; other domains are not blocked.
	for _, kv := range batch {
		if err := gc.backend.Store(ctx, kv.key, kv.value); err != nil {
			gc.restoreContent(ctx, backups)
			return err
		}
	}

	// 2. then update the in-memory index and persist it, so same-process readers
	// can never follow an entry whose content is not yet there
	gc.mu.Lock()
	now := time.Now()
	for _, kv := range batch {
		group := localCacheGroup(kv.key)
		gc.entries[kv.key] = localCacheEntry{
			Group:    group,
			Hash:     localContentHash(kv.value),
			Gen:      tickets[group],
			Modified: now,
		}
	}
	err := gc.saveManifestLocked()
	gc.mu.Unlock()
	if err != nil {
		// the on-disk index still describes the previous version; roll the
		// in-memory copy back and restore the backed-up bytes
		gc.mu.Lock()
		gc.restoreEntries(snapshot)
		gc.mu.Unlock()
		gc.restoreContent(ctx, backups)
		return fmt.Errorf("persisting local cache manifest: %w", err)
	}
	if backupErr != nil {
		gc.logger.Debug("could not back up some prior local cache content; rollback would fall back to storage",
			zap.Error(backupErr))
	}
	return nil
}

// contentBackup holds the previous readable bytes for one key, or marks that
// the key had no content before.
type contentBackup struct {
	key     string
	value   []byte
	existed bool
}

// backupContent reads each batch key's current content before it is replaced.
// A missing key is recorded so restoreContent does not resurrect a file that
// never existed.
func (gc *generationCache) backupContent(ctx context.Context, batch []keyValue) ([]contentBackup, error) {
	backups := make([]contentBackup, 0, len(batch))
	var firstErr error
	for _, kv := range batch {
		value, err := gc.backend.Load(ctx, kv.key)
		switch {
		case err == nil:
			backups = append(backups, contentBackup{key: kv.key, value: value, existed: true})
		case errors.Is(err, fs.ErrNotExist):
			backups = append(backups, contentBackup{key: kv.key, existed: false})
		default:
			if firstErr == nil {
				firstErr = err
			}
			backups = append(backups, contentBackup{key: kv.key, existed: false})
		}
	}
	return backups, firstErr
}

// restoreContent puts backup content back, removing files that did not exist
// before. Errors are logged because the authoritative Storage remains a
// correct fallback.
func (gc *generationCache) restoreContent(ctx context.Context, backups []contentBackup) {
	for _, b := range backups {
		if !b.existed {
			if err := gc.backend.Delete(ctx, b.key); err != nil {
				gc.logger.Warn("removing local cache content after rollback",
					zap.String("key", b.key),
					zap.Error(err))
			}
			continue
		}
		if err := gc.backend.Store(ctx, b.key, b.value); err != nil {
			gc.logger.Warn("restoring local cache content after rollback",
				zap.String("key", b.key),
				zap.Error(err))
		}
	}
}

// Delete invalidates key, or every indexed key under it when key is a
// directory. The index is tombstoned first, with a bumped generation, and the
// content is only recycled after the tombstone is committed, so a concurrent
// reader sees the old complete version or nothing, never a half-deleted site.
func (gc *generationCache) Delete(ctx context.Context, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	gc.mu.Lock()
	if err := gc.ensureLoadedLocked(); err != nil {
		gc.mu.Unlock()
		return err
	}
	affected := gc.keysForDeleteLocked(key)
	gc.mu.Unlock()

	groups := []string{localCacheGroup(key)}
	for _, k := range affected {
		groups = append(groups, localCacheGroup(k))
	}
	sort.Strings(groups)
	groups = uniqueSorted(groups)

	locks := gc.lockGroups(groups)
	defer unlockAll(locks)

	// derive the fencing tokens under the group locks, from a freshly reloaded
	// manifest, so a deletion another instance committed in the meantime cannot
	// be undone by our stale view
	tickets := make(map[string]uint64, len(groups))
	gc.mu.Lock()
	if err := gc.ensureLoadedLocked(); err != nil {
		gc.mu.Unlock()
		return err
	}
	gc.reloadManifestLocked()
	// re-evaluate what is affected against the reloaded index
	affected = gc.keysForDeleteLocked(key)
	for _, group := range groups {
		tickets[group] = gc.nextGenerationLocked(group)
	}

	if len(affected) == 0 {
		gc.mu.Unlock()
		// nothing indexed: still clean up any orphaned content
		return gc.backend.Delete(ctx, key)
	}

	snapshot := make(map[string]localCacheEntry, len(affected))
	for _, k := range affected {
		snapshot[k] = gc.entries[k]
	}

	// 1. update the index: tombstone the entries and commit before touching
	// any content, so readers stop seeing them as complete versions
	now := time.Now()
	for _, k := range affected {
		entry := gc.entries[k]
		entry.Gen = tickets[entry.Group]
		entry.Deleted = true
		entry.Modified = now
		gc.entries[k] = entry
	}
	if err := gc.saveManifestLocked(); err != nil {
		gc.restoreEntries(snapshot)
		gc.mu.Unlock()
		return err
	}
	gc.mu.Unlock()

	// 2. then recycle the content; a failure here leaves bytes that no index
	// entry points at, which can never be served and gets cleaned up later
	for _, k := range affected {
		if err := gc.backend.Delete(ctx, k); err != nil {
			gc.logger.Warn("recycling local cache content after invalidation",
				zap.String("key", k),
				zap.Error(err))
		}
	}
	if err := gc.backend.Delete(ctx, key); err != nil {
		gc.logger.Warn("recycling local cache content after invalidation",
			zap.String("key", key),
			zap.Error(err))
	}
	return nil
}

// keysForDeleteLocked returns the live indexed keys that Delete(key) must
// invalidate: key itself and, when key is a directory, every key below it.
// Callers must hold mu.
func (gc *generationCache) keysForDeleteLocked(key string) []string {
	prefix := key + "/"
	var keys []string
	for k, entry := range gc.entries {
		if entry.Deleted {
			continue
		}
		if k == key || strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// snapshotEntries copies the current entries for batch's keys, including the
// absence of a key, so commitIndex can roll back.
func (gc *generationCache) snapshotEntries(batch []keyValue) map[string]localCacheEntry {
	snapshot := make(map[string]localCacheEntry, len(batch))
	for _, kv := range batch {
		if entry, ok := gc.entries[kv.key]; ok {
			snapshot[kv.key] = entry
		} else {
			snapshot[kv.key] = localCacheEntry{Group: localCacheGroup(kv.key)}
		}
	}
	return snapshot
}

// restoreEntries puts snapshot back, dropping keys that did not exist before.
// Callers must hold mu.
func (gc *generationCache) restoreEntries(snapshot map[string]localCacheEntry) {
	for key, entry := range snapshot {
		if entry.Hash == "" && !entry.Deleted && entry.Gen == 0 {
			delete(gc.entries, key)
			continue
		}
		gc.entries[key] = entry
	}
}

func uniqueSorted(in []string) []string {
	if len(in) < 2 {
		return in
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// The remaining Storage methods are not part of the cache's coordination:
// callers coordinate through the authoritative Storage, so they delegate.
func (gc *generationCache) Exists(ctx context.Context, key string) bool {
	return gc.backend.Exists(ctx, key)
}

func (gc *generationCache) List(ctx context.Context, dir string, recursive bool) ([]string, error) {
	return gc.backend.List(ctx, dir, recursive)
}

func (gc *generationCache) Stat(ctx context.Context, key string) (KeyInfo, error) {
	return gc.backend.Stat(ctx, key)
}

func (gc *generationCache) Lock(ctx context.Context, name string) error {
	return gc.backend.Lock(ctx, name)
}

func (gc *generationCache) Unlock(ctx context.Context, name string) error {
	return gc.backend.Unlock(ctx, name)
}

var _ Storage = (*generationCache)(nil)
