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
	"path"
	"testing"
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

// failOnStore wraps a Storage and fails Store calls for the given key,
// to exercise storeTx rollback.
type failOnStore struct {
	Storage
	failKey string
}

func (f *failOnStore) Store(ctx context.Context, key string, value []byte) error {
	if key == f.failKey {
		return errors.New("injected store failure")
	}
	return f.Storage.Store(ctx, key, value)
}

func TestStoreTxStoresAll(t *testing.T) {
	ctx := context.Background()
	s := &FileStorage{Path: t.TempDir()}

	all := []keyValue{
		{key: "site/example.com.key", value: []byte("key")},
		{key: "site/example.com.crt", value: []byte("cert")},
		{key: "site/example.com.json", value: []byte("meta")},
	}
	if err := storeTx(ctx, s, all); err != nil {
		t.Fatalf("storeTx failed: %v", err)
	}
	for _, kv := range all {
		actual, err := s.Load(ctx, kv.key)
		if err != nil {
			t.Fatalf("loading %s: %v", kv.key, err)
		}
		if string(actual) != string(kv.value) {
			t.Errorf("key %s: expected %q, got %q", kv.key, kv.value, actual)
		}
	}
}

// TestStoreTxRollbackPreservesPrevious ensures that when one file of a
// logical object fails to store, the files already written are rolled
// back to their previous complete versions rather than deleted.
func TestStoreTxRollbackPreservesPrevious(t *testing.T) {
	ctx := context.Background()
	s := &FileStorage{Path: t.TempDir()}

	keys := []string{"site/example.com.key", "site/example.com.crt", "site/example.com.json"}
	for _, key := range keys {
		if err := s.Store(ctx, key, []byte("old:"+key)); err != nil {
			t.Fatalf("storing previous version of %s: %v", key, err)
		}
	}

	// fail on the second file of the object
	wrapped := &failOnStore{Storage: s, failKey: keys[1]}
	all := []keyValue{
		{key: keys[0], value: []byte("new:key")},
		{key: keys[1], value: []byte("new:cert")},
		{key: keys[2], value: []byte("new:meta")},
	}
	if err := storeTx(ctx, wrapped, all); err == nil {
		t.Fatal("expected storeTx to fail, but it succeeded")
	}

	// the previous complete version of the whole object must be intact
	for _, key := range keys {
		actual, err := s.Load(ctx, key)
		if err != nil {
			t.Fatalf("loading %s after rollback: %v", key, err)
		}
		if expected := "old:" + key; string(actual) != expected {
			t.Errorf("key %s: expected previous version %q, got %q", key, expected, actual)
		}
	}
}

// TestStoreTxRollbackRemovesNewKeys ensures that keys which did not
// exist before a failed transaction are removed by the rollback.
func TestStoreTxRollbackRemovesNewKeys(t *testing.T) {
	ctx := context.Background()
	s := &FileStorage{Path: t.TempDir()}

	keys := []string{"site/new.com.key", "site/new.com.crt", "site/new.com.json"}
	wrapped := &failOnStore{Storage: s, failKey: keys[1]}
	all := []keyValue{
		{key: keys[0], value: []byte("key")},
		{key: keys[1], value: []byte("cert")},
		{key: keys[2], value: []byte("meta")},
	}
	if err := storeTx(ctx, wrapped, all); err == nil {
		t.Fatal("expected storeTx to fail, but it succeeded")
	}

	for _, key := range keys {
		if s.Exists(ctx, key) {
			t.Errorf("key %s should not exist after rollback of a failed first publish", key)
		}
	}
}
