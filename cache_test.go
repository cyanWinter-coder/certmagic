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
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	noop := func(Certificate) (*Config, error) { return new(Config), nil }
	c := NewCache(CacheOptions{GetConfigForCert: noop})
	defer c.Stop()

	c.optionsMu.RLock()
	defer c.optionsMu.RUnlock()

	if c.options.RenewCheckInterval != DefaultRenewCheckInterval {
		t.Errorf("Expected RenewCheckInterval to be set to default value, but it wasn't: %s", c.options.RenewCheckInterval)
	}
	if c.options.OCSPCheckInterval != DefaultOCSPCheckInterval {
		t.Errorf("Expected OCSPCheckInterval to be set to default value, but it wasn't: %s", c.options.OCSPCheckInterval)
	}
	if c.options.GetConfigForCert == nil {
		t.Error("Expected GetConfigForCert to be set, but it was nil")
	}
	if c.cache == nil {
		t.Error("Expected cache to be set, but it was nil")
	}
	if c.stopChan == nil {
		t.Error("Expected stopChan to be set, but it was nil")
	}
}

// TestNewCacheWiresRenewalLimits verifies that the renewal concurrency
// options on CacheOptions reach the cache's renewal scheduler, while zero
// values keep the historical unlimited default.
func TestNewCacheWiresRenewalLimits(t *testing.T) {
	noop := func(Certificate) (*Config, error) { return new(Config), nil }

	// Defaults: both limits zero means unlimited and no overrides.
	def := NewCache(CacheOptions{GetConfigForCert: noop})
	def.renewalSchedulerMu.Lock()
	rs := def.renewalScheduler
	def.renewalSchedulerMu.Unlock()
	if rs == nil {
		def.Stop()
		t.Fatal("NewCache did not start a renewal scheduler")
	}
	rs.mu.Lock()
	if rs.globalLimit != 0 || rs.issuerLimit != 0 || len(rs.overrides) != 0 {
		t.Errorf("default scheduler limits = global %d perIssuer %d overrides %v; want 0/0/empty",
			rs.globalLimit, rs.issuerLimit, rs.overrides)
	}
	rs.mu.Unlock()
	def.Stop()

	// Custom limits and a per-issuer override are propagated.
	custom := NewCache(CacheOptions{
		GetConfigForCert:               noop,
		RenewalMaxConcurrency:          4,
		RenewalMaxConcurrencyPerIssuer: 2,
		RenewalIssuerConcurrency:       map[string]int{"special_ca": 1},
	})
	custom.renewalSchedulerMu.Lock()
	rs = custom.renewalScheduler
	custom.renewalSchedulerMu.Unlock()
	rs.mu.Lock()
	if rs.globalLimit != 4 || rs.issuerLimit != 2 || rs.overrides["special_ca"] != 1 {
		t.Errorf("custom scheduler limits = global %d perIssuer %d overrides %v; want 4/2/special_ca=1",
			rs.globalLimit, rs.issuerLimit, rs.overrides)
	}
	rs.mu.Unlock()
	custom.Stop()
}

// TestCacheStopDrainsRenewalGoroutines ensures stopping a cache does not leak
// renewal scheduler goroutines, including when jobs are still queued.
func TestCacheStopDrainsRenewalGoroutines(t *testing.T) {
	noop := func(Certificate) (*Config, error) { return new(Config), nil }
	c := NewCache(CacheOptions{
		GetConfigForCert:      noop,
		RenewalMaxConcurrency: 1,
	})

	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	job := func(context.Context) error {
		entered <- struct{}{}
		<-release
		return nil
	}

	if err := c.getRenewalScheduler().Submit(context.Background(), nil, "renew_stop_1", "issuer_a", job); err != nil {
		t.Fatalf("submit running job: %v", err)
	}
	<-entered
	if err := c.getRenewalScheduler().Submit(context.Background(), nil, "renew_stop_2", "issuer_a", job); err != nil {
		t.Fatalf("submit queued job: %v", err)
	}

	// Stop blocks until the running job finishes; release it in a goroutine.
	stopped := make(chan struct{})
	go func() { c.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned while a renewal job was still running")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the running renewal job finished")
	}

	// No scheduler goroutine may remain.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		buf := make([]byte, 1<<16)
		n := runtime.Stack(buf, true)
		if !strings.Contains(string(buf[:n]), "renewalScheduler.") {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("renewal scheduler goroutines outlived Cache.Stop()")
}
