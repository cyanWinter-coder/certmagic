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
	"errors"
	"io/fs"
	"path"
	"sync"
	"testing"
	"time"
)

func TestPrefixAndKeyBuilders(t *testing.T) {
	am := &ACMEIssuer{CA: "https://example.com/acme-ca/directory"}

	base := path.Join("certificates", "example.com-acme-ca-directory")

	for i, testcase := range []struct {
		in, folder, certFile, keyFile, metaFile string
	}{
		{
			in:       "example.com",
			folder:   path.Join(base, "example.com"),
			certFile: path.Join(base, "example.com", "example.com.crt"),
			keyFile:  path.Join(base, "example.com", "example.com.key"),
			metaFile: path.Join(base, "example.com", "example.com.json"),
		},
		{
			in:       "*.example.com",
			folder:   path.Join(base, "wildcard_.example.com"),
			certFile: path.Join(base, "wildcard_.example.com", "wildcard_.example.com.crt"),
			keyFile:  path.Join(base, "wildcard_.example.com", "wildcard_.example.com.key"),
			metaFile: path.Join(base, "wildcard_.example.com", "wildcard_.example.com.json"),
		},
		{
			// prevent directory traversal! very important, esp. with on-demand TLS
			// see issue #2092
			in:       "a/../../../foo",
			folder:   path.Join(base, "afoo"),
			certFile: path.Join(base, "afoo", "afoo.crt"),
			keyFile:  path.Join(base, "afoo", "afoo.key"),
			metaFile: path.Join(base, "afoo", "afoo.json"),
		},
		{
			in:       "b\\..\\..\\..\\foo",
			folder:   path.Join(base, "bfoo"),
			certFile: path.Join(base, "bfoo", "bfoo.crt"),
			keyFile:  path.Join(base, "bfoo", "bfoo.key"),
			metaFile: path.Join(base, "bfoo", "bfoo.json"),
		},
		{
			in:       "c/foo",
			folder:   path.Join(base, "cfoo"),
			certFile: path.Join(base, "cfoo", "cfoo.crt"),
			keyFile:  path.Join(base, "cfoo", "cfoo.key"),
			metaFile: path.Join(base, "cfoo", "cfoo.json"),
		},
	} {
		if actual := StorageKeys.SiteCert(am.IssuerKey(), testcase.in); actual != testcase.certFile {
			t.Errorf("Test %d: site cert file: Expected '%s' but got '%s'", i, testcase.certFile, actual)
		}
		if actual := StorageKeys.SitePrivateKey(am.IssuerKey(), testcase.in); actual != testcase.keyFile {
			t.Errorf("Test %d: site key file: Expected '%s' but got '%s'", i, testcase.keyFile, actual)
		}
		if actual := StorageKeys.SiteMeta(am.IssuerKey(), testcase.in); actual != testcase.metaFile {
			t.Errorf("Test %d: site meta file: Expected '%s' but got '%s'", i, testcase.metaFile, actual)
		}
	}
}

// leaseTestStorage is a FileStorage wrapper that implements LockLeaseRenewer
// with owner-recorded semantics: it tracks the owner of each lock name and only
// renews or releases the lock when the caller presents the matching owner from
// the context. It lets tests observe renewals and simulate a lease being taken
// over by another worker.
type leaseTestStorage struct {
	*FileStorage

	mu        sync.Mutex
	owners    map[string]string
	renews    int
	loseNext  bool // when true, the next renewal reports the lease as lost
	renewHook func()
}

func newLeaseTestStorage(t *testing.T) *leaseTestStorage {
	t.Helper()
	return &leaseTestStorage{
		FileStorage: &FileStorage{Path: t.TempDir()},
		owners:      make(map[string]string),
	}
}

func (s *leaseTestStorage) Lock(ctx context.Context, name string) error {
	if err := s.FileStorage.Lock(ctx, name); err != nil {
		return err
	}
	owner, _ := LockOwnerFromContext(ctx)
	s.mu.Lock()
	s.owners[name] = owner
	s.mu.Unlock()
	return nil
}

func (s *leaseTestStorage) TryLock(ctx context.Context, name string) (bool, error) {
	ok, err := s.FileStorage.TryLock(ctx, name)
	if ok && err == nil {
		owner, _ := LockOwnerFromContext(ctx)
		s.mu.Lock()
		s.owners[name] = owner
		s.mu.Unlock()
	}
	return ok, err
}

func (s *leaseTestStorage) RenewLockLease(ctx context.Context, name string, _ time.Duration) error {
	s.mu.Lock()
	owner, _ := LockOwnerFromContext(ctx)
	if s.renewHook != nil {
		s.renewHook()
	}
	lose := s.loseNext
	recorded, held := s.owners[name]
	s.renews++
	s.mu.Unlock()

	if lose {
		return ErrLockLeaseLost
	}
	if !held || owner == "" || recorded != owner {
		return ErrLockLeaseLost
	}
	return nil
}

func (s *leaseTestStorage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	owner, _ := LockOwnerFromContext(ctx)
	recorded := s.owners[name]
	delete(s.owners, name)
	s.mu.Unlock()

	// Only the recorded owner may delete the lock file; a stale owner's
	// Unlock must not remove a successor's lock.
	if owner != "" && recorded != "" && owner != recorded {
		return ErrLockLeaseLost
	}
	return s.FileStorage.Unlock(ctx, name)
}

func (s *leaseTestStorage) takeOver(name, newOwner string) {
	s.mu.Lock()
	s.owners[name] = newOwner
	s.mu.Unlock()
}

func (s *leaseTestStorage) renewalCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renews
}

// TestLeaseLockReleaseOnlyByOwner verifies that a stale handle cannot release a
// lock that has since been taken over by another worker (requirement 1 and 3).
func TestLeaseLockReleaseOnlyByOwner(t *testing.T) {
	ctx := context.Background()
	storage := newLeaseTestStorage(t)

	lock, err := acquireLock(ctx, storage, "renew-lock")
	if err != nil {
		t.Fatalf("acquiring lock: %v", err)
	}
	if err := lock.Err(); err != nil {
		t.Fatalf("freshly acquired lease should be valid: %v", err)
	}

	// Simulate the lease expiring while this worker was slow, and another
	// worker acquiring the lock. The new acquisition is registered, replacing
	// our handle, exactly as it would be if it happened in this process.
	storage.takeOver("renew-lock", "someone-else")
	locksMu.Lock()
	locks["renew-lock"] = &lockHandle{storage: storage, lockKey: "renew-lock", owner: "someone-else", leased: true}
	locksMu.Unlock()

	// Releasing the stale handle must not delete the new owner's lock file.
	if err := releaseLock(ctx, lock); !errors.Is(err, ErrLockLeaseLost) {
		t.Fatalf("expected ErrLockLeaseLost releasing a taken-over lock, got: %v", err)
	}
	if _, err := storage.Stat(ctx, "locks/renew-lock.lock"); err != nil {
		t.Fatalf("successor's lock file should still exist, stat: %v", err)
	}

	// Clean up the registry so later tests are unaffected.
	locksMu.Lock()
	delete(locks, "renew-lock")
	locksMu.Unlock()
}

// TestLeaseLockRenewalFailureStopsPublication verifies that a failed renewal
// marks the handle lost, so checkpoints and publication are refused
// (requirements 2 and 5).
func TestLeaseLockRenewalFailureStopsPublication(t *testing.T) {
	ctx := context.Background()
	storage := newLeaseTestStorage(t)

	lock, err := acquireLock(ctx, storage, "renew-lock")
	if err != nil {
		t.Fatalf("acquiring lock: %v", err)
	}
	defer releaseLock(ctx, lock)

	storage.mu.Lock()
	storage.loseNext = true
	storage.mu.Unlock()

	if err := lock.ensureValid(ctx); !errors.Is(err, ErrLockLeaseLost) {
		t.Fatalf("expected ErrLockLeaseLost from failed renewal, got: %v", err)
	}
	if err := lock.ensureValid(ctx); !errors.Is(err, ErrLockLeaseLost) {
		t.Fatalf("expected ErrLockLeaseLost at later checkpoint, got: %v", err)
	}
}

// TestLeaseLockRenewalGoroutineStopsOnRelease verifies that the renewal
// goroutine is cancelled and joined when the task ends, and that renewals stop
// (requirement 4).
func TestLeaseLockRenewalGoroutineStopsOnRelease(t *testing.T) {
	oldPeriod := lockLeaseRenewalPeriod
	lockLeaseRenewalPeriod = 10 * time.Millisecond
	t.Cleanup(func() { lockLeaseRenewalPeriod = oldPeriod })

	ctx := context.Background()
	storage := newLeaseTestStorage(t)

	lock, err := acquireLock(ctx, storage, "renew-lock")
	if err != nil {
		t.Fatalf("acquiring lock: %v", err)
	}

	// Wait for at least one background renewal beyond the initial one.
	deadline := time.Now().Add(2 * time.Second)
	for storage.renewalCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if storage.renewalCount() < 2 {
		t.Fatalf("expected background renewals, got %d", storage.renewalCount())
	}

	if err := releaseLock(ctx, lock); err != nil {
		t.Fatalf("releasing lock: %v", err)
	}
	afterRelease := storage.renewalCount()

	// The joined goroutine cannot renew after release. Give it a few renewal
	// periods to prove it did not.
	time.Sleep(5 * lockLeaseRenewalPeriod)
	if got := storage.renewalCount(); got != afterRelease {
		t.Fatalf("renewal goroutine kept running after release: %d -> %d", afterRelease, got)
	}
}

// TestLeaseLockWithoutLeaseSupportUnchanged verifies that storages which do not
// implement LockLeaseRenewer keep their existing release behavior: Unlock is
// called by name and no renewal goroutine is started (requirement 6).
func TestLeaseLockWithoutLeaseSupportUnchanged(t *testing.T) {
	ctx := context.Background()
	storage := &FileStorage{Path: t.TempDir()}

	lock, err := acquireLock(ctx, storage, "plain-lock")
	if err != nil {
		t.Fatalf("acquiring lock: %v", err)
	}
	if lock.leased {
		t.Fatal("plain FileStorage must not be treated as lease-capable")
	}
	if _, err := storage.Stat(ctx, "locks/plain-lock.lock"); err != nil {
		t.Fatalf("lock file should exist: %v", err)
	}
	if err := lock.ensureValid(ctx); err != nil {
		t.Fatalf("non-lease storage checkpoint must not fail: %v", err)
	}
	if err := releaseLock(ctx, lock); err != nil {
		t.Fatalf("releasing lock: %v", err)
	}
	if _, err := storage.Stat(ctx, "locks/plain-lock.lock"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lock file should have been removed by Unlock, stat: %v", err)
	}
}

// TestLockOwnerTokenPropagates verifies that the owner token installed before
// acquisition is the same one given to the backend on Lock and on every later
// renewal and release, so an owner-aware backend can match them (requirement 1).
func TestLockOwnerTokenPropagates(t *testing.T) {
	ctx := context.Background()
	storage := &ownerRecordingStorage{FileStorage: &FileStorage{Path: t.TempDir()}}

	lock, err := acquireLock(ctx, storage, "owner-lock")
	if err != nil {
		t.Fatalf("acquiring lock: %v", err)
	}
	acquiredOwner := storage.owner("owner-lock")
	if acquiredOwner == "" {
		t.Fatal("backend did not receive an owner token on acquisition")
	}
	if lock.owner != acquiredOwner {
		t.Fatalf("handle owner %q != backend-recorded owner %q", lock.owner, acquiredOwner)
	}

	storage.mu.Lock()
	storage.lastRenewOwner = ""
	storage.mu.Unlock()
	if err := cfgForTest().renewLockLease(ctx, storage, "owner-lock", 0); err != nil {
		t.Fatalf("renewing: %v", err)
	}
	if got := storage.renewOwner(); got != acquiredOwner {
		t.Fatalf("renewal owner %q != acquisition owner %q", got, acquiredOwner)
	}

	if err := releaseLock(ctx, lock); err != nil {
		t.Fatalf("releasing: %v", err)
	}
	if got := storage.lastUnlockOwner(); got != acquiredOwner {
		t.Fatalf("unlock owner %q != acquisition owner %q", got, acquiredOwner)
	}
}

func cfgForTest() *Config { return &Config{Logger: defaultTestLogger} }

// ownerRecordingStorage records the owner token seen on each locking call.
type ownerRecordingStorage struct {
	*FileStorage

	mu             sync.Mutex
	owners         map[string]string
	lastRenewOwner string
	unlockOwner    string
}

func (s *ownerRecordingStorage) Lock(ctx context.Context, name string) error {
	if err := s.FileStorage.Lock(ctx, name); err != nil {
		return err
	}
	owner, _ := LockOwnerFromContext(ctx)
	s.mu.Lock()
	if s.owners == nil {
		s.owners = make(map[string]string)
	}
	s.owners[name] = owner
	s.mu.Unlock()
	return nil
}

func (s *ownerRecordingStorage) RenewLockLease(ctx context.Context, _ string, _ time.Duration) error {
	owner, _ := LockOwnerFromContext(ctx)
	s.mu.Lock()
	s.lastRenewOwner = owner
	s.mu.Unlock()
	return nil
}

func (s *ownerRecordingStorage) Unlock(ctx context.Context, name string) error {
	owner, _ := LockOwnerFromContext(ctx)
	s.mu.Lock()
	s.unlockOwner = owner
	s.mu.Unlock()
	return s.FileStorage.Unlock(ctx, name)
}

func (s *ownerRecordingStorage) owner(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.owners[name]
}

func (s *ownerRecordingStorage) renewOwner() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRenewOwner
}

func (s *ownerRecordingStorage) lastUnlockOwner() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unlockOwner
}

// TestLeaseLockReacquireDoesNotReleaseSuccessor simulates the same process
// re-acquiring a name after the first lease expired: the first (stale) handle's
// release must not remove the lock held by the second acquisition, and the
// second handle remains valid (requirement 3).
func TestLeaseLockReacquireDoesNotReleaseSuccessor(t *testing.T) {
	ctx := context.Background()
	storage := newLeaseTestStorage(t)

	first, err := acquireLock(ctx, storage, "cycle-lock")
	if err != nil {
		t.Fatalf("first acquisition: %v", err)
	}

	// Simulate the first lease being taken over: drop the backend's lock file
	// so the second acquisition can succeed, then acquire again. registerLock
	// replaces the registry entry and joins the first handle's renewal.
	storage.takeOver("cycle-lock", "other-owner")
	if err := storage.FileStorage.Unlock(ctx, "cycle-lock"); err != nil {
		t.Fatalf("removing first lock file: %v", err)
	}
	second, err := acquireLock(ctx, storage, "cycle-lock")
	if err != nil {
		t.Fatalf("second acquisition: %v", err)
	}
	if first == second {
		t.Fatal("expected distinct handles for separate acquisitions")
	}

	// The stale handle must not release the successor's lock.
	if err := releaseLock(ctx, first); !errors.Is(err, ErrLockLeaseLost) {
		t.Fatalf("expected stale release to report ErrLockLeaseLost, got: %v", err)
	}
	if _, err := storage.Stat(ctx, "locks/cycle-lock.lock"); err != nil {
		t.Fatalf("successor's lock file should still exist, stat: %v", err)
	}
	if err := second.Err(); err != nil {
		t.Fatalf("successor's handle should still be valid: %v", err)
	}

	// The current owner can still release normally.
	if err := releaseLock(ctx, second); err != nil {
		t.Fatalf("releasing current lock: %v", err)
	}
	if _, err := storage.Stat(ctx, "locks/cycle-lock.lock"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lock file should be gone after owner release, stat: %v", err)
	}
}
