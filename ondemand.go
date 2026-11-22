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
	"fmt"
	"sync"
	"time"
)

// onDemandLoadTimeout caps how long any single handshake is willing to
// wait for another goroutine's in-flight load/obtain to reach a terminal
// state before giving up on its own.
const onDemandLoadTimeout = 2 * time.Minute

// onDemandObtainTimeout bounds the lifetime of an on-demand issuance. It is
// applied to the application's own context, which is detached from the
// triggering handshakes, so a client disconnect cannot stretch or cancel
// the work other waiters still depend on.
const onDemandObtainTimeout = 180 * time.Second

// onDemandApplication is the shared lifecycle of a single on-demand
// certificate application for one canonical identity (see canonicalName).
//
// State boundaries, in order:
//
//  1. The first handshake for an identity creates the application and
//     becomes its leader; every later handshake for the same identity
//     joins as a waiter. There is at most one application per identity at
//     a time.
//  2. The leader runs the load/obtain work on a context detached from the
//     triggering handshakes. A waiter that gives up (its own handshake
//     context is canceled, or its wait timeout elapses) simply stops
//     waiting; it never cancels the shared application.
//  3. On success the leader publishes the certificate into the in-memory
//     cache (and, for managed certs, storage) before closing done, so
//     every waiter observes the same terminal state: either the published
//     certificate or the recorded error.
//  4. On failure no terminal certificate is published and the slot is
//     released from the registry, allowing the next explicit request to
//     start a fresh application rather than inheriting a dead result.
//
// done is closed exactly once, when the application reaches a terminal
// state. cert/err are written before that close and never mutated
// afterwards, so a reader only needs the close for synchronization.
type onDemandApplication struct {
	// done is closed when the leader has finished (successfully or not).
	done chan struct{}

	// Terminal outcome, populated before done is closed.
	cert Certificate
	err  error
}

// onDemandCoordinator hands out the shared application for each canonical
// identity, creating one on first use and reusing it for every concurrent
// handshake that arrives while it is in flight.
type onDemandCoordinator struct {
	mu           sync.Mutex
	applications map[string]*onDemandApplication
}

// join returns the shared application for name. The bool reports whether
// the caller is the leader (true) that must run the work, or a waiter
// (false) that should block on app.done.
func (c *onDemandCoordinator) join(name string) (*onDemandApplication, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if app, ok := c.applications[name]; ok {
		return app, false
	}
	app := &onDemandApplication{done: make(chan struct{})}
	c.applications[name] = app
	return app, true
}

// finish records the terminal outcome, releases the identity's slot so a
// later request can start a new application, and wakes every waiter. It
// must be called exactly once, by the leader.
func (c *onDemandCoordinator) finish(name string, app *onDemandApplication, cert Certificate, err error) {
	c.mu.Lock()
	// Only release the slot if it still points at this application; a
	// defensive check in case finish were ever invoked twice.
	if current := c.applications[name]; current == app {
		delete(c.applications, name)
	}
	app.cert = cert
	app.err = err
	close(app.done)
	c.mu.Unlock()
}

// await blocks until the application reaches its terminal state or the
// waiter's own context is done (e.g. the client disconnected) / its wait
// budget elapses. It returns the leader's terminal outcome once available.
//
// Crucially, returning early here has no effect on the application: the
// leader keeps running and other waiters are untouched.
func (app *onDemandApplication) await(ctx context.Context, name string) (Certificate, error) {
	timeout := time.NewTimer(onDemandLoadTimeout)
	defer timeout.Stop()
	select {
	case <-timeout.C:
		return Certificate{}, fmt.Errorf("timed out waiting to load certificate for %s", name)
	case <-ctx.Done():
		return Certificate{}, ctx.Err()
	case <-app.done:
		return app.cert, app.err
	}
}

// leaderContext returns the context under which the shared load/obtain
// work runs. It inherits values (e.g. the ClientHelloInfo consumed by
// DecisionFunc/event handlers) from the triggering handshake but NOT its
// cancellation: once an application has started, no single waiter's
// disconnect is allowed to abort work the remaining waiters depend on.
// A fixed budget still bounds the work so the slot cannot leak forever.
func leaderContext(handshakeCtx context.Context) (context.Context, context.CancelFunc) {
	if handshakeCtx == nil {
		handshakeCtx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(handshakeCtx), onDemandObtainTimeout)
}

// certApplications is the process-wide registry of in-flight on-demand
// applications. It is keyed by canonical identity, so case variants,
// trailing-dot variants and IDN/punycode variants of one host converge on
// the same application.
var certApplications = &onDemandCoordinator{
	applications: make(map[string]*onDemandApplication),
}
