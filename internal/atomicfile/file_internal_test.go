package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCloseVerifiesContents ensures that a temp file whose on-disk
// contents no longer match what was written is never renamed over the
// destination, and that the failed publish cleans up after itself.
func TestCloseVerifiesContents(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "test-file")

	af, err := newFile(dest, 0o600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	f := af.(*atomicFile)
	if _, err := f.Write([]byte("good content")); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	tmpName := f.f.Name()

	// corrupt the temp file out from under the writer, simulating a
	// torn or intercepted write
	if err := os.WriteFile(tmpName, []byte("corrupted!"), 0o600); err != nil {
		t.Fatalf("failed to corrupt temp file: %v", err)
	}

	if err := f.Close(); err == nil {
		t.Fatal("expected Close to fail on checksum mismatch, but it succeeded")
	}

	// the destination must not have been created
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("destination should not exist after failed publish, stat err: %v", err)
	}
	// the temp file must have been removed
	if _, err := os.Stat(tmpName); !os.IsNotExist(err) {
		t.Errorf("temp file should have been removed after failed publish, stat err: %v", err)
	}
}

// TestCloseVerifiesContentsPreservesPrevious ensures a failed publish
// leaves the previous complete version of the destination intact.
func TestCloseVerifiesContentsPreservesPrevious(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "test-file")
	const previous = "previous complete version"
	if err := os.WriteFile(dest, []byte(previous), 0o600); err != nil {
		t.Fatalf("failed to write previous version: %v", err)
	}

	af, err := newFile(dest, 0o600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	f := af.(*atomicFile)
	if _, err := f.Write([]byte("new content")); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if err := os.WriteFile(f.f.Name(), []byte("corrupted!"), 0o600); err != nil {
		t.Fatalf("failed to corrupt temp file: %v", err)
	}
	if err := f.Close(); err == nil {
		t.Fatal("expected Close to fail on checksum mismatch, but it succeeded")
	}

	actual, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("failed to read destination: %v", err)
	}
	if string(actual) != previous {
		t.Errorf("expected previous version to be preserved, got %q", string(actual))
	}
}

// TestStaleTempCleanup ensures that temp files orphaned by a crashed
// writer are removed once stale, while fresh temp files (possibly
// being written by another live process) and unrelated files are
// left alone.
func TestStaleTempCleanup(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "test-file")
	prefix := tempPrefix(dest)

	stale := filepath.Join(dir, prefix+"stale")
	fresh := filepath.Join(dir, prefix+"fresh")
	unrelated := filepath.Join(dir, "unrelated.tmp-123")
	for _, name := range []string{stale, fresh, unrelated} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("failed to create %s: %v", name, err)
		}
	}
	old := time.Now().Add(-2 * staleTempMaxAge)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatalf("failed to age stale temp file: %v", err)
	}

	af, err := newFile(dest, 0o600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer af.Cancel()

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale temp file should have been cleaned up, stat err: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("fresh temp file should have been kept, stat err: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated file should have been kept, stat err: %v", err)
	}
}

// TestCancelAfterFailedClose ensures Cancel remains idempotent even
// after a failed Close, and never removes the destination.
func TestCancelAfterFailedClose(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "test-file")

	af, err := newFile(dest, 0o600)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	f := af.(*atomicFile)
	if _, err := f.Write([]byte("content")); err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if err := os.WriteFile(f.f.Name(), []byte("corrupted!"), 0o600); err != nil {
		t.Fatalf("failed to corrupt temp file: %v", err)
	}
	if err := f.Close(); err == nil {
		t.Fatal("expected Close to fail")
	}
	if err := f.Cancel(); err != nil {
		t.Errorf("Cancel after failed Close should be a no-op, got: %v", err)
	}
}
