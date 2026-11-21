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
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/idna"
)

// defaultMaxConcurrentIssuances bounds how many certificate issuance
// operations may run at the same time. Issuance can block on network I/O
// (ACME transactions, challenge propagation, storage locks), so a bound
// keeps a burst of handshakes for distinct names from exhausting
// goroutines and file descriptors.
const defaultMaxConcurrentIssuances = 10

// issuanceQueue coordinates certificate issuance/renewal work that may be
// requested concurrently by many handshakes.
//
// A request is identified by a canonicalized domain name (see
// issuanceKey), so equivalent spellings of the same domain -- differing
// only in case, a trailing dot, or IDN encoding (Unicode vs. punycode) --
// share a single work item. Every waiter on a work item observes its
// terminal result; the work itself runs on a context detached from any
// individual waiter, so one waiter's cancellation can never abort work
// others are still waiting on. After a work item reaches its terminal
// state it is removed from the coordinator, so a failure does not poison
// future requests: the next explicit request starts a fresh attempt.
//
// Work items are dispatched from a FIFO queue by a bounded worker pool,
// which gives distinct domains submission-order access to the limited
// concurrency budget instead of letting one slow domain occupy every
// worker. Every completion, failure, cancellation and panic path releases
// the work item and its worker slot, so neither channels nor goroutines
// leak.
type issuanceQueue struct {
	mu            sync.Mutex
	maxConcurrent int
	activeWorkers int
	queue         []*issuanceWork
	inflight      map[string]*issuanceWork
}

// issuanceWork is a single shared issuance operation, identified by key.
// The first submitter for a key supplies run; later submitters simply
// attach to the same item and wait on done.
type issuanceWork struct {
	key    string
	logger *zap.Logger

	// run executes the actual issuance. It is invoked once per work item,
	// on a context whose cancellation is independent of any individual
	// waiter's context. Its non-error return value is published on the
	// item so every waiter observes the same product.
	run func(ctx context.Context) (any, error)

	// done is closed exactly once, when run returns (including after a
	// recovered panic). Waiters select on it together with their own
	// contexts, so no per-waiter registration is needed and a canceled
	// waiter cannot strand any bookkeeping.
	done chan struct{}
	err  error

	// resultMu guards result, which is written by the worker goroutine
	// executing run and read by potentially later-joining waiter
	// goroutines (including after the coordinator has removed the item
	// and a replacement item for the same key exists).
	resultMu sync.RWMutex
	result   any

	// waiters counts goroutines currently blocked in wait. It lets
	// lifecycle tests deterministically observe coalescing without
	// relying on scheduler timing.
	waiters atomic.Int32
}

// setResult publishes the shared product of run.
func (w *issuanceWork) setResult(v any) {
	w.resultMu.Lock()
	w.result = v
	w.resultMu.Unlock()
}

// resultOf returns the shared result stored on the work item after it
// finishes, or the zero value of T if none was stored.
func resultOf[T any](w *issuanceWork) T {
	w.resultMu.RLock()
	defer w.resultMu.RUnlock()
	var zero T
	if w.result == nil {
		return zero
	}
	v, _ := w.result.(T)
	return v
}

// newIssuanceQueue returns an empty coordinator with the default
// concurrency bound.
func newIssuanceQueue() *issuanceQueue {
	return &issuanceQueue{
		maxConcurrent: defaultMaxConcurrentIssuances,
		inflight:      make(map[string]*issuanceWork),
	}
}

// issuanceKey canonicalizes a domain name so equivalent identifiers map
// to the same key. It applies, in order:
//
//   - surrounding whitespace trimming
//   - lower-casing (DNS names are case-insensitive)
//   - a single trailing root-dot removal ("example.com." == "example.com")
//   - IDNA ToASCII conversion, so a Unicode name and its punycode form
//     collapse to one key
//
// Wildcard names ("*.example.com") are canonicalized label by label so
// the wildcard marker survives IDNA processing. If IDNA processing fails
// (e.g. an IP literal or another non-domain identifier), the trimmed,
// lower-cased, dot-stripped input is used as-is rather than dropping
// deduplication for that identifier.
func issuanceKey(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return name
	}
	if strings.HasPrefix(name, "*.") {
		rest, err := idna.Lookup.ToASCII(strings.TrimPrefix(name, "*."))
		if err != nil {
			return name
		}
		return "*." + rest
	}
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return name
	}
	return ascii
}

// submit enqueues work for key. If an equivalent work item is already
// queued or running, run is ignored and the caller joins the existing
// item; otherwise the item is created with run and appended to the FIFO
// queue.
//
// The returned work item's result must be consumed with wait. submit
// never blocks on the work itself.
func (q *issuanceQueue) submit(logger *zap.Logger, key string, run func(ctx context.Context) (any, error)) *issuanceWork {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.inflight == nil {
		q.inflight = make(map[string]*issuanceWork)
	}
	if w, ok := q.inflight[key]; ok {
		return w
	}

	w := &issuanceWork{
		key:    key,
		logger: logger,
		run:    run,
		done:   make(chan struct{}),
	}
	q.inflight[key] = w
	q.queue = append(q.queue, w)

	if q.activeWorkers < q.maxConcurrent {
		q.activeWorkers++
		go q.worker()
	}
	return w
}

// wait blocks until the work item reaches its terminal state or ctx is
// done. A canceled or timed-out ctx returns ctx.Err() to this caller
// only: the shared work keeps running and every waiter that remains (or
// arrives later) still receives the work's terminal result. On a clean
// completion the work item's own error is returned, identically to every
// other waiter.
func (w *issuanceWork) wait(ctx context.Context) error {
	w.waiters.Add(1)
	defer w.waiters.Add(-1)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.done:
		return w.err
	}
}

// has reports whether a work item for key is currently queued or
// running. It is used by callers that need to know whether equivalent
// work is already in flight before deciding how to handle a request.
func (q *issuanceQueue) has(key string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	_, ok := q.inflight[key]
	return ok
}

// worker pops work items from the FIFO queue until it is empty. Each
// item runs exactly once; the worker slot is always released, including
// after a recovered panic, so the concurrency budget cannot drift.
func (q *issuanceQueue) worker() {
	defer func() {
		if err := recover(); err != nil {
			buf := make([]byte, stackTraceBufferSize)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("panic: certificate issuance worker: %v\n%s", err, buf)
		}
		q.mu.Lock()
		q.activeWorkers--
		q.mu.Unlock()
	}()

	for {
		q.mu.Lock()
		if len(q.queue) == 0 {
			q.mu.Unlock()
			return
		}
		w := q.queue[0]
		q.queue = q.queue[1:]
		q.mu.Unlock()

		q.runWork(w)
	}
}

// runWork executes a single work item and drives it through every
// lifecycle transition. The work context is detached from the
// submitter's context so that a single waiter's cancellation cannot
// terminate shared issuance. All exit paths -- success, ordinary error,
// and panic -- close the item and release the coordinator's references.
func (q *issuanceQueue) runWork(w *issuanceWork) {
	// The issuance itself must outlive any one handshake. A timeout
	// still applies at the caller via wait, and the underlying ACME
	// operations honor their own contexts, so the only effect of
	// detaching cancellation is isolating individual waiters.
	ctx := context.WithoutCancel(context.Background())

	var result any
	err := func() (err error) {
		defer func() {
			if p := recover(); p != nil {
				buf := make([]byte, stackTraceBufferSize)
				buf = buf[:runtime.Stack(buf, false)]
				log.Printf("panic: certificate issuance for %s: %v\n%s", w.key, p, buf)
				err = errors.New("certificate issuance panicked")
			}
		}()
		result, err = w.run(ctx)
		return err
	}()

	// Publish the product before closing done so any waiter unblocked by
	// the close observes it. resultMu additionally guards against a
	// waiter holding a reference to a finished item that a replacement
	// item has since superseded in the coordinator.
	if err == nil {
		w.setResult(result)
	} else if w.logger != nil {
		// Centralized failure logging: fire-and-forget submissions (e.g.
		// a background renewal whose handshake already returned the
		// unexpired cert) have no waiter to observe the error, so it would
		// otherwise be lost silently.
		w.logger.Error("certificate issuance job failed",
			zap.String("identifier", w.key), zap.Error(err))
	}
	w.err = err
	close(w.done)

	q.mu.Lock()
	delete(q.inflight, w.key)
	q.mu.Unlock()
}

// onDemandIssuanceTimeout bounds how long a handshake waits for an
// on-demand issuance or renewal, including time spent queued behind
// other domains. It mirrors the historical fixed 2-minute waiter
// timeout while now honoring real context cancellation as well.
const onDemandIssuanceTimeout = 2 * time.Minute

// onDemandWorkTimeout bounds the detached issuance work itself, so a
// stuck ACME transaction cannot run forever after every waiter has gone
// away. It preserves the historical 180s ceiling the issuance operated
// under (previously applied to the handshake-scoped context).
const onDemandWorkTimeout = 180 * time.Second
