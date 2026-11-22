/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
Package atomicfile provides a mechanism (on Unix-like platforms) to present a consistent view of a file to separate
processes even while the file is being written.  This is accomplished by writing a temporary file, syncing to disk,
verifying the synced contents against a checksum of what was written, and only then renaming over the destination
file name. After the rename, the containing directory is synced so the rename itself is durable.

Partial/inconsistent reads can occur due to:
 1. A process attempting to read the file while it is being written to (both in the case of a new file with a
    short/incomplete write or in the case of an existing, updated file where new bytes may be written at the beginning
    but old bytes may still be present after).
 2. Concurrent goroutines leading to multiple active writers of the same file.

The above mechanism explicitly protects against (1) as all writes are to a file with a temporary name, and readers
only ever open the previous complete generation or the next complete one. If the process exits between writing the
temporary file and renaming it, the destination file is left untouched and the orphaned temporary file — recognizable
by its ".<name>.tmp-" prefix — is removed by a later writer once it is stale, bounding the cleanup.

There is no explicit protection against multiple, concurrent goroutines attempting to write the same file. However,
atomically writing the file should mean only one writer will "win" and a consistent file will be visible.

Note: atomicfile is partially implemented for Windows. The Windows codepath performs the same operations, however
Windows does not guarantee that a rename operation is atomic; a crash in the middle may leave the destination file
truncated rather than with the expected content.
*/
package atomicfile

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// File is an io.ReadWriteCloser that can also be Canceled if a change needs to be abandoned.
type File interface {
	io.ReadWriteCloser
	// Cancel abandons a change to a file. This can be called if a write fails or another error occurs.
	Cancel() error
}

// ErrClosed is returned if Read or Write are called on a closed File.
var ErrClosed = errors.New("file is closed")

// staleTempMaxAge is how old a temporary file must be before a new
// writer considers it orphaned by a crashed process and removes it.
// It is a variable so tests can adjust it.
var staleTempMaxAge = time.Hour

// New returns a new atomic file.  On Unix-like platforms, the writer (an io.ReadWriteCloser) is backed by a temporary
// file placed into the same directory as the destination file (using filepath.Dir to split the directory from the
// name).  On a call to Close the temporary file is synced to disk, its contents are verified against a checksum of
// everything that was written, and only then is it renamed to its final name, hiding any previous file by the same
// name. The directory is then synced so the rename survives a crash.
//
// Note: Take care to call Close and handle any errors that are returned.  Errors returned from Close may indicate that
// the file was not written with its final name.
func New(name string, mode os.FileMode) (File, error) {
	return newFile(name, mode)
}

type atomicFile struct {
	name     string
	f        *os.File
	hash     hash.Hash // checksum of everything written so far
	closed   bool
	closedMu sync.RWMutex
}

// tempPrefix returns the prefix used for temporary files that will be
// renamed to name. Embedding the destination's base name makes temp
// files orphaned by a crash recognizable, so a later writer can
// clean them up.
func tempPrefix(name string) string {
	return "." + filepath.Base(name) + ".tmp-"
}

func newFile(name string, mode os.FileMode) (File, error) {
	dir := filepath.Dir(name)
	// bounded cleanup: best-effort removal of temp files orphaned by
	// previous writers of this destination that crashed before renaming
	cleanupStaleTemps(dir, tempPrefix(name), staleTempMaxAge)
	f, err := os.CreateTemp(dir, tempPrefix(name))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, fmt.Errorf("failed to change temp file permissions: %w", err)
	}
	return &atomicFile{name: name, f: f, hash: sha256.New()}, nil
}

func (a *atomicFile) Close() (err error) {
	a.closedMu.Lock()
	defer a.closedMu.Unlock()

	if a.closed {
		return nil
	}
	a.closed = true

	defer func() {
		if err != nil {
			_ = os.Remove(a.f.Name()) // ignore errors
		}
	}()
	// The order of operations here is:
	// 1. sync the temp file's contents to disk
	// 2. verify the synced contents against the checksum of what was written
	// 3. close the temp file
	// 4. rename the temp file over the destination
	// 5. sync the directory so the rename itself is durable
	// The destination is only replaced after steps 1-3 succeed, so a
	// crash or error at any point leaves the previous complete version
	// of the file in place. While the ordering of 3 and 4 is not
	// important on Unix-like operating systems, Windows cannot rename
	// an open file. By closing first, we allow the rename operation to
	// succeed.
	if err = a.f.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file %q: %w", a.f.Name(), err)
	}
	if err = a.verify(); err != nil {
		return fmt.Errorf("failed to verify temp file %q: %w", a.f.Name(), err)
	}
	if err = a.f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file %q: %w", a.f.Name(), err)
	}
	if err = os.Rename(a.f.Name(), a.name); err != nil {
		return fmt.Errorf("failed to rename %q to %q: %w", a.f.Name(), a.name, err)
	}
	// make the rename itself durable, so a crash cannot resurrect the
	// previous generation of the file; directory syncs are not
	// supported on all platforms, so failure there is not fatal
	if derr := syncDir(filepath.Dir(a.name)); derr != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("failed to sync directory of %q: %w", a.name, derr)
	}
	return nil
}

// verify re-reads the temp file and compares its contents against the
// checksum of everything that was written, so a torn or corrupted
// temp file is never renamed over the destination.
func (a *atomicFile) verify() error {
	if _, err := a.f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seeking to start of temp file: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(h, a.f); err != nil {
		return fmt.Errorf("reading back temp file: %w", err)
	}
	if !bytes.Equal(h.Sum(nil), a.hash.Sum(nil)) {
		return errors.New("checksum mismatch: temp file contents differ from what was written")
	}
	return nil
}

func (a *atomicFile) Cancel() error {
	a.closedMu.Lock()
	defer a.closedMu.Unlock()

	if a.closed {
		return nil
	}
	a.closed = true
	_ = a.f.Close() // ignore error
	err := os.Remove(a.f.Name())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (a *atomicFile) Read(p []byte) (n int, err error) {
	a.closedMu.RLock()
	defer a.closedMu.RUnlock()
	if a.closed {
		return 0, ErrClosed
	}
	return a.f.Read(p)
}

func (a *atomicFile) Write(p []byte) (n int, err error) {
	a.closedMu.RLock()
	defer a.closedMu.RUnlock()
	if a.closed {
		return 0, ErrClosed
	}
	n, err = a.f.Write(p)
	a.hash.Write(p[:n])
	return n, err
}

// cleanupStaleTemps removes temp files in dir matching prefix that are
// older than maxAge. It is best-effort: any error simply leaves the
// temp file in place for a later cleanup pass.
func cleanupStaleTemps(dir, prefix string, maxAge time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

// syncDir flushes the directory itself to stable storage so that a
// rename within it survives a crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
