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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Storage is a type that implements a key-value store with
// basic file system (folder path) semantics. Keys use the
// forward slash '/' to separate path components and have no
// leading or trailing slashes.
//
// A "prefix" of a key is defined on a component basis,
// e.g. "a" is a prefix of "a/b" but not "ab/c".
//
// A "file" is a key with a value associated with it.
//
// A "directory" is a key with no value, but which may be
// the prefix of other keys.
//
// Keys passed into Load and Store always have "file" semantics,
// whereas "directories" are only implicit by leading up to the
// file.
//
// The Load, List, and Stat methods should return fs.ErrNotExist
// if the key does not exist. Delete is different: see its method
// comment (missing keys are not an error).
//
// Processes running in a cluster should use the same Storage
// value (with the same configuration) in order to share
// certificates and other TLS resources with the cluster.
//
// Implementations of Storage MUST be safe for concurrent use
// and honor context cancellations. Methods should block until
// their operation is complete; that is, Load() should always
// return the value from the last call to Store() for a given
// key, and concurrent calls to Store() should not corrupt a
// file.
//
// For simplicity, this is not a streaming API and is not
// suitable for very large files.
type Storage interface {
	// Locker enables the storage backend to synchronize
	// operational units of work.
	//
	// The use of Locker is NOT employed around every
	// Storage method call (Store, Load, etc), as these
	// should already be thread-safe. Locker is used for
	// high-level jobs or transactions that need
	// synchronization across a cluster; it's a simple
	// distributed lock. For example, CertMagic uses the
	// Locker interface to coordinate the obtaining of
	// certificates.
	Locker

	// Store puts value at key. It creates the key if it does
	// not exist and overwrites any existing value at this key.
	Store(ctx context.Context, key string, value []byte) error

	// Load retrieves the value at key.
	Load(ctx context.Context, key string) ([]byte, error)

	// Delete deletes the named key. If the name is a
	// directory (i.e. prefix of other keys), all keys
	// prefixed by this key should be deleted. It is not
	// an error if the key does not exist (including when
	// it was already deleted); return nil in that case.
	// Return an error only if the key still exists when
	// the method returns (the delete did not fully apply).
	Delete(ctx context.Context, key string) error

	// Exists returns true if the key exists either as
	// a directory (prefix to other keys) or a file,
	// and there was no error checking.
	Exists(ctx context.Context, key string) bool

	// List returns all keys in the given path.
	//
	// If recursive is true, non-terminal keys
	// will be enumerated (i.e. "directories"
	// should be walked); otherwise, only keys
	// prefixed exactly by prefix will be listed.
	List(ctx context.Context, path string, recursive bool) ([]string, error)

	// Stat returns information about key.
	Stat(ctx context.Context, key string) (KeyInfo, error)
}

// Locker facilitates synchronization across machines and networks.
// It essentially provides a distributed named-mutex service so
// that multiple consumers can coordinate tasks and share resources.
//
// If possible, a Locker should implement a coordinated distributed
// locking mechanism by generating fencing tokens (see
// https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html).
// This typically requires a central server or consensus algorithm
// However, if that is not feasible, Lockers may implement an
// alternative mechanism that uses timeouts to detect node or network
// failures and avoid deadlocks. For example, the default FileStorage
// writes a timestamp to the lock file every few seconds, and if another
// node acquiring the lock sees that timestamp is too old, it may
// assume the lock is stale.
//
// As not all Locker implementations use fencing tokens, code relying
// upon Locker must be tolerant of some mis-synchronizations but can
// expect them to be rare.
//
// This interface should only be used for coordinating expensive
// operations across nodes in a cluster; not for internal, extremely
// short-lived, or high-contention locks.
type Locker interface {
	// Lock acquires the lock for name, blocking until the lock
	// can be obtained or an error is returned. Only one lock
	// for the given name can exist at a time. A call to Lock for
	// a name which already exists blocks until the named lock
	// is released or becomes stale.
	//
	// If the named lock represents an idempotent operation, callers
	// should always check to make sure the work still needs to be
	// completed after acquiring the lock. You never know if another
	// process already completed the task while you were waiting to
	// acquire it.
	//
	// Implementations should honor context cancellation.
	Lock(ctx context.Context, name string) error

	// Unlock releases named lock. This method must ONLY be called
	// after a successful call to Lock, and only after the critical
	// section is finished, even if it errored or timed out. Unlock
	// cleans up any resources allocated during Lock. Unlock should
	// only return an error if the lock was unable to be released.
	Unlock(ctx context.Context, name string) error
}

type TryLocker interface {
	// TryLock attempts to acquire the lock for name, and returns a
	// boolean that reports whether the lock was successfully aquired
	// or not along with any errors that may have occurred.
	//
	// Implementations should honor context cancellation.
	TryLock(ctx context.Context, name string) (bool, error)

	// Unlock releases named lock. This method must ONLY be called
	// after a successful call to TryLock, and only after the critical
	// section is finished, even if it errored or timed out. Unlock
	// cleans up any resources allocated during TryLock. Unlock should
	// only return an error if the lock was unable to be released.
	Unlock(ctx context.Context, name string) error
}

// LockLeaseRenewer is an optional interface that can be implemented by a Storage
// implementation to support renewing the lease on a lock. This is useful for
// long-running operations that need to be synchronized across a cluster.
//
// A lease is not ownership by itself. Renewals and releases must act only on a
// lock the caller still holds: once a lease expired, was taken over, or was
// released, RenewLockLease must fail with ErrLockLeaseLost rather than extending
// (or otherwise touching) whatever lock record now exists under that name.
//
// Implementations that can record an owner should read it from the context with
// LockOwnerFromContext and persist it with the lock record, then verify it
// before renewing or releasing. That way a slow or stale owner can never renew
// or delete its successor's lock. Implementations that cannot record an owner
// may ignore the context value; they remain valid.
type LockLeaseRenewer interface {
	// RenewLockLease renews the lease on the lock for the given lockKey for the
	// given leaseDuration. This is used to prevent the lock from being acquired
	// by another process.
	//
	// If the context carries an owner (see LockOwnerFromContext), only that
	// owner may renew the lock. The call must return ErrLockLeaseLost if the
	// lock is no longer held by the caller.
	RenewLockLease(ctx context.Context, lockKey string, leaseDuration time.Duration) error
}

// ErrLockLeaseLost indicates that the caller no longer owns a lock lease,
// because it expired, was taken over, or was released. It is returned by
// LockLeaseRenewer implementations and used internally to signal that work done
// under the lock must stop and must not be published.
var ErrLockLeaseLost = errors.New("lock lease lost")

// lockOwnerCtxKey carries the owner token of a lock acquisition. It is placed
// on the context passed to Lock, TryLock, RenewLockLease, and Unlock so that
// storage implementations supporting ownership can record and verify it without
// changing the Locker interface; implementations that are unaware of it keep
// working exactly as before.
type lockOwnerCtxKey struct{}

// LockOwnerFromContext returns the owner token of the lock acquisition that the
// context belongs to, if any. Storage implementations that record an owner for
// each lock should persist this value and verify it before renewing or
// releasing the lock, so that a stale owner cannot affect a successor's lock.
func LockOwnerFromContext(ctx context.Context) (string, bool) {
	owner, ok := ctx.Value(lockOwnerCtxKey{}).(string)
	return owner, ok && owner != ""
}

// withLockOwner returns a context carrying owner for calls into the storage
// backend's locking methods.
func withLockOwner(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, lockOwnerCtxKey{}, owner)
}

// KeyInfo holds information about a key in storage.
// Key and IsTerminal are required; Modified and Size
// are optional if the storage implementation is not
// able to get that information. Setting them will
// make certain operations more consistent or
// predictable, but it is not crucial to basic
// functionality.
type KeyInfo struct {
	Key        string
	Modified   time.Time
	Size       int64
	IsTerminal bool // false for directories (keys that act as prefix for other keys)
}

// storeTx stores all the values or none at all.
func storeTx(ctx context.Context, s Storage, all []keyValue) error {
	for i, kv := range all {
		err := s.Store(ctx, kv.key, kv.value)
		if err != nil {
			for j := i - 1; j >= 0; j-- {
				s.Delete(ctx, all[j].key)
			}
			return err
		}
	}
	return nil
}

// keyValue pairs a key and a value.
type keyValue struct {
	key   string
	value []byte
}

// KeyBuilder provides a namespace for methods that
// build keys and key prefixes, for addressing items
// in a Storage implementation.
type KeyBuilder struct{}

// CertsPrefix returns the storage key prefix for
// the given certificate issuer.
func (keys KeyBuilder) CertsPrefix(issuerKey string) string {
	return path.Join(prefixCerts, keys.Safe(issuerKey))
}

// CertsSitePrefix returns a key prefix for items associated with
// the site given by domain using the given issuer key.
func (keys KeyBuilder) CertsSitePrefix(issuerKey, domain string) string {
	return path.Join(keys.CertsPrefix(issuerKey), keys.Safe(domain))
}

// SiteCert returns the path to the certificate file for domain
// that is associated with the issuer with the given issuerKey.
func (keys KeyBuilder) SiteCert(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsSitePrefix(issuerKey, domain), safeDomain+".crt")
}

// SitePrivateKey returns the path to the private key file for domain
// that is associated with the certificate from the given issuer with
// the given issuerKey.
func (keys KeyBuilder) SitePrivateKey(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsSitePrefix(issuerKey, domain), safeDomain+".key")
}

// SiteMeta returns the path to the metadata file for domain that
// is associated with the certificate from the given issuer with
// the given issuerKey.
func (keys KeyBuilder) SiteMeta(issuerKey, domain string) string {
	safeDomain := keys.Safe(domain)
	return path.Join(keys.CertsSitePrefix(issuerKey, domain), safeDomain+".json")
}

// OCSPStaple returns a key for the OCSP staple associated
// with the given certificate. If you have the PEM bundle
// handy, pass that in to save an extra encoding step.
func (keys KeyBuilder) OCSPStaple(cert *Certificate, pemBundle []byte) string {
	var ocspFileName string
	if len(cert.Names) > 0 {
		firstName := keys.Safe(cert.Names[0])
		ocspFileName = firstName + "-"
	}
	ocspFileName += fastHash(pemBundle)
	return path.Join(prefixOCSP, ocspFileName)
}

// Safe standardizes and sanitizes str for use as
// a single component of a storage key. This method
// is idempotent.
func (keys KeyBuilder) Safe(str string) string {
	str = strings.ToLower(str)
	str = strings.TrimSpace(str)

	// replace a few specific characters
	repl := strings.NewReplacer(
		" ", "_",
		"+", "_plus_",
		"*", "wildcard_",
		":", "-",
		"..", "", // prevent directory traversal (regex allows single dots)
	)
	str = repl.Replace(str)

	// finally remove all non-word characters
	return safeKeyRE.ReplaceAllLiteralString(str, "")
}

// CleanUpOwnLocks immediately cleans up all
// current locks obtained by this process. Since
// this does not cancel the operations that
// the locks are synchronizing, this should be
// called only immediately before process exit.
// Errors are only reported if a logger is given.
func CleanUpOwnLocks(ctx context.Context, logger *zap.Logger) {
	locksMu.Lock()
	handles := make([]*lockHandle, 0, len(locks))
	for _, handle := range locks {
		handles = append(handles, handle)
	}
	locksMu.Unlock()

	for _, handle := range handles {
		if err := releaseLock(ctx, handle); err != nil {
			logger.Error("unable to clean up lock in storage backend",
				zap.Any("storage", handle.storage),
				zap.String("lock_key", handle.lockKey),
				zap.Error(err))
		}
	}
}

// lockHandle represents one successful acquisition of a named lock by this
// process. Every acquisition gets a fresh owner token so that a release or
// renewal performed after the lock was lost and re-acquired cannot act on the
// successor's lock.
//
// For storages that implement LockLeaseRenewer, the handle also owns the
// goroutine that keeps the lease alive for as long as the protected work runs.
type lockHandle struct {
	storage Storage
	lockKey string
	owner   string

	// leased is true when the storage implements LockLeaseRenewer; only then
	// does the handle participate in lease ownership semantics.
	leased bool

	mu            sync.Mutex
	renewMu       sync.Mutex // serializes renewals for this handle
	lost          bool
	leaseDuration time.Duration
	cancel        context.CancelFunc
	done          chan struct{}
}

// Err returns ErrLockLeaseLost (wrapped) if the handle's lease is no longer
// known to be valid. Callers must consult this at safety checkpoints: after a
// renewal failure, work done under the lock must stop and must not be
// published, because another worker may have taken over the lock meanwhile.
func (h *lockHandle) Err() error {
	if h == nil || !h.leased {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lost {
		return fmt.Errorf("%w: lock %q", ErrLockLeaseLost, h.lockKey)
	}
	return nil
}

// markLost records that the lock lease is no longer provably held. It reports
// whether this call made the transition, so the loss is logged only once.
func (h *lockHandle) markLost() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lost {
		return false
	}
	h.lost = true
	return true
}

// stopRenewal cancels the lease renewal goroutine, if any, and waits for it to
// exit, so a finished task leaves no goroutine behind. It is safe to call more
// than once (and concurrently): only one caller cancels, but every caller waits
// for the goroutine to actually finish.
func (h *lockHandle) stopRenewal() {
	h.mu.Lock()
	cancel, done := h.cancel, h.done
	h.cancel = nil
	h.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// renewWith renews the lock's lease for leaseDuration and marks the handle lost
// if renewal fails. A failed renewal means the lease may already have expired,
// so it is no longer safe to treat the lock as held. It also records
// leaseDuration as the duration the renewal goroutine should keep asking for,
// since retries extend how long the protected work may take.
//
// Renewal is refused if this handle is no longer the registered owner of the
// lock: a stale handle must never extend (or otherwise touch) a lease now held
// by a successor.
func (h *lockHandle) renewWith(ctx context.Context, leaseDuration time.Duration) error {
	if !h.leased {
		return nil
	}

	// Only one renewal may be in flight at a time, so that a slow background
	// renewal cannot interleave with a checkpoint renewal or a release.
	h.renewMu.Lock()
	defer h.renewMu.Unlock()

	locksMu.Lock()
	current := locks[h.lockKey]
	locksMu.Unlock()
	if current != h {
		h.markLost()
		return fmt.Errorf("%w: lock %q was re-acquired by another worker", ErrLockLeaseLost, h.lockKey)
	}

	h.mu.Lock()
	h.leaseDuration = leaseDuration
	h.mu.Unlock()

	renewer := h.storage.(LockLeaseRenewer)
	err := renewer.RenewLockLease(withLockOwner(ctx, h.owner), h.lockKey, leaseDuration)
	if err != nil {
		// Cancellation (e.g. the operation ended, or the renewal goroutine is
		// being stopped by release) says nothing about the lease itself, so it
		// must not be mistaken for lease loss -- unless the backend explicitly
		// reports the lease lost.
		if !errors.Is(err, ErrLockLeaseLost) &&
			(ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return err
		}
		if h.markLost() {
			defaultLogger.Sugar().Errorf("lock lease lost for %s (owner %s): %v - stopping protected work because another worker may hold the lock", h.lockKey, h.owner, err)
		}
		if !errors.Is(err, ErrLockLeaseLost) {
			err = fmt.Errorf("%w: %v", ErrLockLeaseLost, err)
		}
		return err
	}
	return nil
}

// currentLeaseDuration returns the lease duration the renewal goroutine should
// request.
func (h *lockHandle) currentLeaseDuration() time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.leaseDuration > 0 {
		return h.leaseDuration
	}
	return lockLeaseDuration
}

// ensureValid is a safety checkpoint used right before publishing results: for
// storages with leases it actively renews the lease, so a lease that expired
// without a previously recorded failure is still detected. Non-lease storages
// always pass, preserving their existing behavior.
func (h *lockHandle) ensureValid(ctx context.Context) error {
	if h == nil || !h.leased {
		return nil
	}
	if err := h.Err(); err != nil {
		return err
	}
	return h.renewWith(ctx, h.currentLeaseDuration())
}

// startLeaseRenewal keeps the handle's lease alive until it is released,
// renewing it periodically until the handle is released or renewal fails.
// The initial renewal is performed synchronously by registerLock so that a
// lease which cannot be renewed at all is known before any protected work runs.
func (h *lockHandle) startLeaseRenewal() {
	if !h.leased {
		return
	}

	// The renewal goroutine must not inherit cancellation of the operation
	// context: it lives until release, which always cancels it.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	h.mu.Lock()
	h.cancel = cancel
	h.done = done
	h.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(lockLeaseRenewalPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := h.renewWith(ctx, h.currentLeaseDuration()); err != nil {
					// The lease is lost (or the handle is being stopped); stop
					// renewing. The handle remains registered so the deferred
					// release can still join this goroutine (it will not delete
					// the successor's lock).
					return
				}
			}
		}
	}()
}

// newLockOwner returns a token that uniquely identifies one lock acquisition.
// It only needs to be unique among acquisitions this process could confuse with
// one another; it is never used as a secret.
func newLockOwner() string {
	var token [16]byte
	if _, err := rand.Read(token[:]); err == nil {
		return hex.EncodeToString(token[:])
	}
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), atomic.AddUint64(&lockOwnerCounter, 1))
}

func registerLock(ctx context.Context, storage Storage, lockKey string) *lockHandle {
	_, leased := storage.(LockLeaseRenewer)
	owner, _ := LockOwnerFromContext(ctx)
	if owner == "" {
		owner = newLockOwner()
	}
	handle := &lockHandle{
		storage:       storage,
		lockKey:       lockKey,
		owner:         owner,
		leased:        leased,
		leaseDuration: lockLeaseDuration,
	}

	locksMu.Lock()
	previous := locks[lockKey]
	locks[lockKey] = handle
	locksMu.Unlock()

	// If this name had an older acquisition in this process, that acquisition
	// can no longer be the owner (a second successful acquisition of the same
	// name means the first was released or its lease was lost). Stop its
	// renewal goroutine so it cannot attempt to extend a lease that no longer
	// belongs to it; it is joined so no goroutine is left behind.
	if previous != nil {
		previous.stopRenewal()
	}

	if !leased {
		return handle
	}

	// Renew once synchronously so the caller learns immediately (via the
	// handle) whether the backend still considers this acquisition its own;
	// the protected flow checks before doing any work. A failure here is not
	// returned as an acquisition error: the lock was obtained, it just may not
	// be provably held long enough to use. In that case no renewal goroutine is
	// started, since the handle is already marked lost.
	if err := handle.renewWith(ctx, lockLeaseDuration); err == nil {
		handle.startLeaseRenewal()
	}
	return handle
}

// acquireLock obtains the named lock and registers a handle for it. The owner
// token is placed on the context before acquisition so storages that can record
// an owner do so atomically with the acquisition.
func acquireLock(ctx context.Context, storage Storage, lockKey string) (*lockHandle, error) {
	ctx = withLockOwner(ctx, newLockOwner())
	if err := storage.Lock(ctx, lockKey); err != nil {
		return nil, err
	}
	return registerLock(ctx, storage, lockKey), nil
}

func tryAcquireLock(ctx context.Context, storage Storage, lockKey string) (*lockHandle, bool, error) {
	locker, ok := storage.(TryLocker)
	if !ok {
		return nil, false, fmt.Errorf("%T does not implement TryLocker", storage)
	}

	ctx = withLockOwner(ctx, newLockOwner())
	ok, err := locker.TryLock(ctx, lockKey)
	if !ok || err != nil {
		return nil, ok, err
	}
	return registerLock(ctx, storage, lockKey), true, nil
}

func releaseLock(ctx context.Context, handle *lockHandle) error {
	if handle == nil {
		return nil
	}

	// Stop this handle's renewal before releasing, so a renewal cannot land
	// after the lock is gone and touch a successor's lock. This also joins the
	// goroutine, so a finished task leaves none behind.
	handle.stopRenewal()

	// Storages without lease support keep their historical behavior: Unlock is
	// always attempted by name.
	if !handle.leased {
		err := handle.storage.Unlock(context.WithoutCancel(ctx), handle.lockKey)
		if err == nil {
			unregisterLock(handle)
		}
		return err
	}

	// Only the current owner may release a lock. If this handle is no longer
	// the registered acquisition of the name (it was replaced by a newer one,
	// or already released), calling Unlock by name could delete a successor's
	// lock, so leave it alone. (The backend's lease expiry cleans it up.)
	locksMu.Lock()
	current, ok := locks[handle.lockKey]
	locksMu.Unlock()
	if !ok || current != handle {
		if handle.Err() != nil {
			return handle.Err()
		}
		return fmt.Errorf("%w: lock %q is no longer held by this worker", ErrLockLeaseLost, handle.lockKey)
	}

	// If the lease was lost, the backend cannot prove ownership from the name
	// alone and another worker may hold the lock now; do not delete it.
	if err := handle.Err(); err != nil {
		unregisterLock(handle)
		return err
	}

	err := handle.storage.Unlock(withLockOwner(context.WithoutCancel(ctx), handle.owner), handle.lockKey)
	if err == nil {
		unregisterLock(handle)
	}
	return err
}

// unregisterLock removes handle from the registry if it is still the current
// acquisition of its lock. It never removes a successor's entry.
func unregisterLock(handle *lockHandle) {
	locksMu.Lock()
	if locks[handle.lockKey] == handle {
		delete(locks, handle.lockKey)
	}
	locksMu.Unlock()
}

// locks stores the lock handles currently acquired by this process. The owner
// token in each handle distinguishes separate acquisitions of the same name.
var locks = make(map[string]*lockHandle)
var locksMu sync.Mutex
var lockOwnerCounter uint64

// lockLeaseDuration is the lease duration requested for lock leases, and
// lockLeaseRenewalPeriod is how often the lease is renewed while the lock is
// held. Both are variables so tests can use short intervals. Renewing three
// times per lease leaves room for a retry or two before the lease is
// considered lost.
var (
	lockLeaseDuration      = retryIntervals[0] + DefaultACME.CertObtainTimeout
	lockLeaseRenewalPeriod = lockLeaseDuration / 3
)

// StorageKeys provides methods for accessing
// keys and key prefixes for items in a Storage.
// Typically, you will not need to use this
// because accessing storage is abstracted away
// for most cases. Only use this if you need to
// directly access TLS assets in your application.
var StorageKeys KeyBuilder

const (
	prefixCerts = "certificates"
	prefixOCSP  = "ocsp"
)

// safeKeyRE matches any undesirable characters in storage keys.
// Note that this allows dots, so you'll have to strip ".." manually.
var safeKeyRE = regexp.MustCompile(`[^\w@.-]`)

// defaultFileStorage is a convenient, default storage
// implementation using the local file system.
var defaultFileStorage = &FileStorage{Path: dataDir()}
