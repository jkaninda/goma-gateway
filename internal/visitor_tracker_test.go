/*
 * Copyright 2024 Jonas Kaninda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package internal

import (
	"context"
	"testing"
	"time"
)

// Stop drains whatever is still queued before returning, which is what makes
// the async write path testable without sleeping.
func TestVisitorTrackerCountsDistinctVisitors(t *testing.T) {
	vt := NewVisitorTracker(Config{TTL: time.Minute, CleanupInterval: time.Hour, Store: NewMemoryStore()})

	vt.AddVisitor("10.0.0.1", "Chrome")
	vt.AddVisitor("10.0.0.1", "Chrome") // same visitor, second request
	vt.AddVisitor("10.0.0.2", "Chrome")
	vt.AddVisitor("10.0.0.1", "Firefox") // same ip, different agent = different visitor
	if err := vt.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}

	got, err := vt.GetVisitorCount(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if got != 3 {
		t.Fatalf("visitor count = %d, want 3", got)
	}
}

// The store holds the salted hash, never the address — the gauge must not turn
// Redis into a log of who visited.
func TestVisitorTrackerStoresNoRawIP(t *testing.T) {
	store := NewMemoryStore()
	vt := NewVisitorTracker(Config{TTL: time.Minute, CleanupInterval: time.Hour, Store: store})
	vt.AddVisitor("203.0.113.7", "Chrome")
	_ = vt.Stop()

	store.mu.RLock()
	defer store.mu.RUnlock()
	for id := range store.seen {
		if id == "203.0.113.7" || len(id) == 0 {
			t.Fatalf("stored id %q looks like a raw address", id)
		}
	}
	if len(store.seen) != 1 {
		t.Fatalf("stored %d ids, want 1", len(store.seen))
	}
}

// Counting is by last-seen, so a visitor goes idle on time even if no sweep has
// run yet — the old implementation returned the map size and over-counted.
func TestMemoryStoreCountIsTTLAccurate(t *testing.T) {
	s := NewMemoryStore()
	now := time.Now()
	if err := s.Touch(context.Background(), []string{"fresh"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Touch(context.Background(), []string{"stale"}, now.Add(-10*time.Minute)); err != nil {
		t.Fatal(err)
	}

	got, err := s.Count(context.Background(), now.Add(-5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("count before sweep = %d, want 1 (stale visitor counted)", got)
	}

	if err := s.Sweep(context.Background(), now.Add(-5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.mu.RLock()
	n := len(s.seen)
	s.mu.RUnlock()
	if n != 1 {
		t.Fatalf("after sweep %d entries remain, want 1", n)
	}
}

// A burst must never block the response: past the queue size, samples are
// dropped instead.
func TestAddVisitorNeverBlocks(t *testing.T) {
	// No run() goroutine, so nothing drains — every send has to fall through.
	vt := &VisitorTracker{
		store: NewMemoryStore(),
		ttl:   time.Minute,
		queue: make(chan string, 4),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < visitorQueueSize*2; i++ {
			vt.AddVisitor("10.0.0.1", "Chrome")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("AddVisitor blocked when the queue was full")
	}
}

func TestVisitorTrackerNilSafe(t *testing.T) {
	var vt *VisitorTracker
	vt.AddVisitor("10.0.0.1", "Chrome") // must not panic
	if n, err := vt.GetVisitorCount(context.Background()); err != nil || n != 0 {
		t.Fatalf("nil tracker count = %d, %v; want 0, nil", n, err)
	}
	if err := vt.Stop(); err != nil {
		t.Fatalf("nil tracker stop: %v", err)
	}
	// Stop is idempotent on a live tracker too.
	live := NewVisitorTracker(Config{TTL: time.Minute, Store: NewMemoryStore()})
	_ = live.Stop()
	if err := live.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}

// monitoring.visitorTTL is operator input: a bad value must not stop the gateway
// from starting, and a value that would make the gauge meaningless is clamped.
func TestVisitorTTLConfig(t *testing.T) {
	cases := []struct {
		raw  string
		want time.Duration
	}{
		{"", defaultVisitorTTL},          // unset
		{"   ", defaultVisitorTTL},       // blank
		{"2m", 2 * time.Minute},          // the API-gateway case
		{"90s", 90 * time.Second},        // seconds are fine
		{"1h", time.Hour},                // long windows are the operator's call
		{"5s", minVisitorTTL},            // below the republish interval: clamped
		{"0s", defaultVisitorTTL},        // zero is meaningless
		{"-1m", defaultVisitorTTL},       // negative is meaningless
		{"soon", defaultVisitorTTL},      // unparseable
		{"5 minutes", defaultVisitorTTL}, // not a Go duration
	}
	for _, tc := range cases {
		if got := visitorTTL(tc.raw); got != tc.want {
			t.Errorf("visitorTTL(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

// The tracker is only built when metrics are on, and it honours the configured
// window.
func TestNewVisitorTrackerFromMonitoring(t *testing.T) {
	if vt := newVisitorTracker(Monitoring{EnableMetrics: false, VisitorTTL: "2m"}); vt != nil {
		_ = vt.Stop()
		t.Fatal("built a tracker with metrics disabled")
	}
	vt := newVisitorTracker(Monitoring{EnableMetrics: true, VisitorTTL: "2m"})
	if vt == nil {
		t.Fatal("no tracker with metrics enabled")
	}
	defer func() { _ = vt.Stop() }()
	if vt.ttl != 2*time.Minute {
		t.Fatalf("ttl = %v, want 2m", vt.ttl)
	}
}

// Shutdown calls Stop through the Router interface, including when metrics are
// off and there is no tracker to stop.
func TestRouterStop(t *testing.T) {
	var r Router = &router{}
	if err := r.Stop(); err != nil {
		t.Fatalf("stop with no tracker: %v", err)
	}
	withTracker := &router{visitors: newVisitorTracker(Monitoring{EnableMetrics: true})}
	if err := withTracker.Stop(); err != nil {
		t.Fatalf("stop with tracker: %v", err)
	}
}
