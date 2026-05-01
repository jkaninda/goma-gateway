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
	"net/http"
	"net/http/httptest"
	"testing"
)

func reqWithHeader(name, value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if name != "" {
		r.Header.Set(name, value)
	}
	return r
}

func resetUnavailable() {
	for k := range unavailableBackends {
		delete(unavailableBackends, k)
	}
}

// Exclusive canary with a matching rule wins outright.
func TestSelectCanaryBackend_ExclusiveMatchWins(t *testing.T) {
	resetUnavailable()
	stable := &Backend{Endpoint: "http://stable", Weight: 10}
	canary := &Backend{
		Endpoint:  "http://canary",
		Weight:    1,
		Exclusive: true,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{stable, canary}

	got := backends.SelectCanaryBackend(reqWithHeader("X-Beta", "true"))
	if got == nil || got.Endpoint != canary.Endpoint {
		t.Fatalf("expected exclusive canary to win, got %+v", got)
	}
}

// When multiple exclusive canaries match, the higher Priority wins.
func TestSelectCanaryBackend_PriorityResolvesOverlap(t *testing.T) {
	resetUnavailable()
	low := &Backend{
		Endpoint:  "http://canary-low",
		Exclusive: true,
		Priority:  1,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	high := &Backend{
		Endpoint:  "http://canary-high",
		Exclusive: true,
		Priority:  10,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	// Low listed first on purpose — priority must override config order.
	backends := Backends{low, high}

	got := backends.SelectCanaryBackend(reqWithHeader("X-Beta", "true"))
	if got == nil || got.Endpoint != high.Endpoint {
		t.Fatalf("expected higher-priority canary to win, got %+v", got)
	}
}

// At equal priority, the first matching backend in config order wins.
func TestSelectCanaryBackend_PriorityTieFirstMatchWins(t *testing.T) {
	resetUnavailable()
	first := &Backend{
		Endpoint:  "http://canary-first",
		Exclusive: true,
		Priority:  5,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	second := &Backend{
		Endpoint:  "http://canary-second",
		Exclusive: true,
		Priority:  5,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{first, second}

	got := backends.SelectCanaryBackend(reqWithHeader("X-Beta", "true"))
	if got == nil || got.Endpoint != first.Endpoint {
		t.Fatalf("expected first matching canary to win on tie, got %+v", got)
	}
}

// Non-exclusive canaries must not be returned by SelectCanaryBackend even when
// their match rules are satisfied — they belong in the shared pool.
func TestSelectCanaryBackend_IgnoresNonExclusive(t *testing.T) {
	resetUnavailable()
	canary := &Backend{
		Endpoint:  "http://canary",
		Weight:    20,
		Exclusive: false,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{canary}

	if got := backends.SelectCanaryBackend(reqWithHeader("X-Beta", "true")); got != nil {
		t.Fatalf("non-exclusive match must not win exclusive selection, got %+v", got)
	}
}

// A matching exclusive canary marked unavailable must be skipped.
func TestSelectCanaryBackend_SkipsUnavailable(t *testing.T) {
	resetUnavailable()
	unavailableBackends["http://canary-down"] = true
	t.Cleanup(resetUnavailable)

	down := &Backend{
		Endpoint:  "http://canary-down",
		Exclusive: true,
		Priority:  10,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	up := &Backend{
		Endpoint:  "http://canary-up",
		Exclusive: true,
		Priority:  1,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{down, up}

	got := backends.SelectCanaryBackend(reqWithHeader("X-Beta", "true"))
	if got == nil || got.Endpoint != up.Endpoint {
		t.Fatalf("expected live lower-priority canary to win over unavailable high-priority, got %+v", got)
	}
}

// Pool selection: when a non-exclusive canary matches, it joins stable
// backends under weighted selection. Running many trials should hit both.
func TestSelectFromNonExclusivePool_CanaryJoinsStable(t *testing.T) {
	resetUnavailable()
	stable := &Backend{Endpoint: "http://stable", Weight: 50}
	canary := &Backend{
		Endpoint:  "http://canary",
		Weight:    50,
		Exclusive: false,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{stable, canary}

	seen := map[string]int{}
	for i := 0; i < 400; i++ {
		b := backends.selectFromNonExclusivePool(reqWithHeader("X-Beta", "true"))
		if b == nil {
			t.Fatalf("expected a selection, got nil")
		}
		seen[b.Endpoint]++
	}
	if seen[stable.Endpoint] == 0 || seen[canary.Endpoint] == 0 {
		t.Fatalf("expected both stable and canary to be picked, got %+v", seen)
	}
}

// Pool selection: a non-matching non-exclusive canary is excluded from the
// pool, leaving only stable backends.
func TestSelectFromNonExclusivePool_ExcludesNonMatchingCanary(t *testing.T) {
	resetUnavailable()
	stable := &Backend{Endpoint: "http://stable", Weight: 10}
	canary := &Backend{
		Endpoint:  "http://canary",
		Weight:    10,
		Exclusive: false,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{stable, canary}

	for i := 0; i < 50; i++ {
		b := backends.selectFromNonExclusivePool(reqWithHeader("", ""))
		if b == nil || b.Endpoint != stable.Endpoint {
			t.Fatalf("expected stable-only selection, got %+v", b)
		}
	}
}

// Pool selection: exclusive canaries are never pooled, even when they match.
func TestSelectFromNonExclusivePool_ExcludesExclusiveCanary(t *testing.T) {
	resetUnavailable()
	stable := &Backend{Endpoint: "http://stable", Weight: 10}
	exclusiveCanary := &Backend{
		Endpoint:  "http://canary-exclusive",
		Weight:    10,
		Exclusive: true,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{stable, exclusiveCanary}

	for i := 0; i < 50; i++ {
		b := backends.selectFromNonExclusivePool(reqWithHeader("X-Beta", "true"))
		if b == nil || b.Endpoint != stable.Endpoint {
			t.Fatalf("exclusive canary must not be pooled, got %+v", b)
		}
	}
}

// Pool selection: when there are no stable backends and no matching
// non-exclusive canaries, the pool is empty and selection returns nil so the
// caller can emit a 503.
func TestSelectFromNonExclusivePool_EmptyPoolReturnsNil(t *testing.T) {
	resetUnavailable()
	canary := &Backend{
		Endpoint:  "http://canary",
		Weight:    10,
		Exclusive: false,
		Match: []BackendMatch{
			{Source: SourceTypeHeader, Name: "X-Beta", Operator: OperatorEquals, Value: "true"},
		},
	}
	backends := Backends{canary}

	if got := backends.selectFromNonExclusivePool(reqWithHeader("", "")); got != nil {
		t.Fatalf("expected nil when no backend is eligible, got %+v", got)
	}
}
