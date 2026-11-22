package certmagic_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/caddyserver/certmagic/internal/testutil"
)

func TestFileStorageStoreLoad(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	err = s.Store(ctx, "foo", []byte("bar"))
	testutil.RequireNoError(t, err)
	dat, err := s.Load(ctx, "foo")
	testutil.RequireNoError(t, err)
	testutil.RequireEqualValues(t, dat, []byte("bar"))
}

func TestFileStorageStoreLoadRace(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	a := bytes.Repeat([]byte("a"), 4096*1024)
	b := bytes.Repeat([]byte("b"), 4096*1024)
	err = s.Store(ctx, "foo", a)
	testutil.RequireNoError(t, err)
	done := make(chan struct{})
	go func() {
		err := s.Store(ctx, "foo", b)
		testutil.RequireNoError(t, err)
		close(done)
	}()
	dat, err := s.Load(ctx, "foo")
	<-done
	testutil.RequireNoError(t, err)
	testutil.RequireEqualValues(t, 4096*1024, len(dat))
}

func TestFileStorageWriteLock(t *testing.T) {
	ctx := context.Background()
	tmpDir, err := os.MkdirTemp(os.TempDir(), "certmagic*")
	testutil.RequireNoError(t, err, "allocating tmp dir")
	defer os.RemoveAll(tmpDir)
	s := &certmagic.FileStorage{
		Path: tmpDir,
	}
	// cctx is a cancelled ctx. so if we can't immediately get the lock, it will fail
	cctx, cn := context.WithCancel(ctx)
	cn()
	// should success
	err = s.Lock(cctx, "foo")
	testutil.RequireNoError(t, err)
	// should fail
	err = s.Lock(cctx, "foo")
	testutil.RequireError(t, err)

	err = s.Unlock(cctx, "foo")
	testutil.RequireNoError(t, err)
	// shouldn't fail
	err = s.Lock(cctx, "foo")
	testutil.RequireNoError(t, err)

	err = s.Unlock(cctx, "foo")
	testutil.RequireNoError(t, err)
}

// TestFileStorageStoreIdempotent ensures that publishing the same
// content repeatedly is a no-op and that no temp files are left behind.
func TestFileStorageStoreIdempotent(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	s := &certmagic.FileStorage{Path: tmpDir}

	value := []byte("the same content, published twice")
	err := s.Store(ctx, "foo", value)
	testutil.RequireNoError(t, err)
	err = s.Store(ctx, "foo", value)
	testutil.RequireNoError(t, err)

	dat, err := s.Load(ctx, "foo")
	testutil.RequireNoError(t, err)
	testutil.RequireEqualValues(t, value, dat)

	// publishing different content still takes effect
	err = s.Store(ctx, "foo", []byte("new content"))
	testutil.RequireNoError(t, err)
	dat, err = s.Load(ctx, "foo")
	testutil.RequireNoError(t, err)
	testutil.RequireEqualValues(t, []byte("new content"), dat)

	// no temp files may be left behind by any of the publishes
	entries, err := os.ReadDir(tmpDir)
	testutil.RequireNoError(t, err)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", entry.Name())
		}
	}
}

// TestFileStorageConcurrentReadersSeeCompleteFiles ensures that while
// a key is being replaced, readers only ever load the complete old
// generation or the complete new one — never a truncated or torn file.
func TestFileStorageConcurrentReadersSeeCompleteFiles(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	s := &certmagic.FileStorage{Path: tmpDir}

	genA := bytes.Repeat([]byte("a"), 256*1024)
	genB := bytes.Repeat([]byte("b"), 512*1024)
	err := s.Store(ctx, "foo", genA)
	testutil.RequireNoError(t, err)

	const iterations = 50
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < iterations; i++ {
			// alternate generations
			if i%2 == 0 {
				_ = s.Store(ctx, "foo", genB)
			} else {
				_ = s.Store(ctx, "foo", genA)
			}
		}
	}()

	for i := 0; i < iterations; i++ {
		dat, err := s.Load(ctx, "foo")
		testutil.RequireNoError(t, err)
		if !bytes.Equal(dat, genA) && !bytes.Equal(dat, genB) {
			t.Fatalf("loaded torn or unknown generation of length %d", len(dat))
		}
	}
	<-done
}
