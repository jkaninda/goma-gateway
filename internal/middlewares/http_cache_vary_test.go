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

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// varyingBackend answers with the value of one request header, and says so.
func varyingBackend(field string, calls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		w.Header().Set("Vary", field)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("body for " + r.Header.Get(field)))
	})
}

func newTestCache(cfg HttpCacheConfig) HttpCacheConfig {
	cfg.Path = "/"
	cfg.Paths = []string{testAllPaths}
	if cfg.Name == "" {
		cfg.Name = "test"
	}
	cfg.TTL = time.Minute
	cfg.Cache = NewHttpCacheMiddleware(false, time.Minute, 1<<20)
	return cfg
}

func get(t *testing.T, handler http.Handler, header, value string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/data", nil)
	if header != "" {
		r.Header.Set(header, value)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestCacheKeysOnVaryRatherThanRefusing(t *testing.T) {
	var calls int
	cache := newTestCache(HttpCacheConfig{})
	handler := cache.Middleware(varyingBackend("Origin", &calls))

	first := get(t, handler, "Origin", "https://a.example")
	if got := first.Header().Get(constGomaCacheHeader); got != "MISS" {
		t.Errorf("first request: %s = %q, want MISS", constGomaCacheHeader, got)
	}

	second := get(t, handler, "Origin", "https://a.example")
	if got := second.Header().Get(constGomaCacheHeader); got != "HIT" {
		t.Errorf("repeat of the same Origin: %s = %q, want HIT", constGomaCacheHeader, got)
	}
	if calls != 1 {
		t.Errorf("upstream calls = %d, want 1: the second request should have been served from cache", calls)
	}
	if got := second.Header().Get("Vary"); got != "origin" {
		t.Errorf("Vary = %q, want the field the entry was keyed on replayed to downstream caches", got)
	}

	// A different Origin must not read the first caller's entry.
	other := get(t, handler, "Origin", "https://b.example")
	if calls != 2 {
		t.Errorf("upstream calls = %d, want 2: a different Origin must not share the entry", calls)
	}
	if body := other.Body.String(); body != "body for https://b.example" {
		t.Errorf("body = %q, want the response produced for this Origin", body)
	}
}

func TestCacheIgnoresVaryOnCredentialHeaders(t *testing.T) {
	for _, field := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		t.Run(field, func(t *testing.T) {
			var calls int
			cache := newTestCache(HttpCacheConfig{})
			handler := cache.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Vary", field+", Accept-Encoding")
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("public body"))
			}))

			get(t, handler, "", "")
			second := get(t, handler, "", "")

			if got := second.Header().Get(constGomaCacheHeader); got != "HIT" {
				t.Errorf("%s = %q, want HIT: a Vary on %s is already covered by the credential rules",
					constGomaCacheHeader, got, field)
			}
			if calls != 1 {
				t.Errorf("upstream calls = %d, want 1", calls)
			}
		})
	}
}

func TestCacheIgnoreVaryConfig(t *testing.T) {
	var calls int
	cache := newTestCache(HttpCacheConfig{IgnoreVary: []string{"X-Region"}})
	handler := cache.Middleware(varyingBackend("X-Region", &calls))

	get(t, handler, "X-Region", "eu")
	second := get(t, handler, "X-Region", "us")

	if got := second.Header().Get(constGomaCacheHeader); got != "HIT" {
		t.Errorf("%s = %q, want HIT: X-Region was declared not to change the body", constGomaCacheHeader, got)
	}
	if calls != 1 {
		t.Errorf("upstream calls = %d, want 1: an ignored Vary must not split the entry", calls)
	}
}

func TestCacheAnnouncesWhyItDidNotStore(t *testing.T) {
	tests := map[string]struct {
		header, value, want string
	}{
		"no-store":            {"Cache-Control", "no-store", "the response is marked no-store"},
		"sets a cookie":       {"Set-Cookie", "session=abc", "the response sets a cookie"},
		"varies on the world": {"Vary", "*", "the response varies on everything"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cache := newTestCache(HttpCacheConfig{})
			handler := cache.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(tc.header, tc.value)
				_, _ = w.Write([]byte("body"))
			}))

			response := get(t, handler, "", "")
			if got := response.Header().Get(constGomaCacheHeader); got != "BYPASS" {
				t.Errorf("%s = %q, want BYPASS rather than a MISS that never becomes a HIT",
					constGomaCacheHeader, got)
			}
			if got := response.Header().Get(constGomaCacheReasonHeader); got != tc.want {
				t.Errorf("%s = %q, want %q", constGomaCacheReasonHeader, got, tc.want)
			}
			if got := response.Header().Get(constGomaCacheMaxAgeHeader); got != "" {
				t.Errorf("%s = %q, want it dropped: nothing was stored to have an age",
					constGomaCacheMaxAgeHeader, got)
			}
		})
	}
}

func TestCacheAnnouncesCredentialedBypass(t *testing.T) {
	cache := newTestCache(HttpCacheConfig{})
	handler := cache.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("body"))
	}))

	response := get(t, handler, headerAuthorize, "Bearer alice")
	if got := response.Header().Get(constGomaCacheHeader); got != "BYPASS" {
		t.Errorf("%s = %q, want BYPASS", constGomaCacheHeader, got)
	}
	if got := response.Header().Get(constGomaCacheReasonHeader); got != "the request carried credentials" {
		t.Errorf("%s = %q, want the credentialed-request reason", constGomaCacheReasonHeader, got)
	}
}

func TestCacheRefusesTooManyVaryFields(t *testing.T) {
	cache := HttpCacheConfig{Name: "test"}
	header := http.Header{}
	header.Set("Vary", "A, B, C, D")

	fields, reason, ok := cache.storability(header, http.StatusOK)
	if ok {
		t.Errorf("storability said a response varying on 4 headers may be cached, fields=%v", fields)
	}
	if reason == "" {
		t.Error("no reason given for refusing the response")
	}
}

func TestCacheControlIsReadAsTokensAcrossAllLines(t *testing.T) {
	cache := HttpCacheConfig{Name: "test"}

	secondLine := http.Header{}
	secondLine.Add("Cache-Control", "max-age=60")
	secondLine.Add("Cache-Control", "no-store")
	if _, _, ok := cache.storability(secondLine, http.StatusOK); ok {
		t.Error("a no-store on a second Cache-Control line was missed")
	}

	qualified := http.Header{}
	qualified.Set("Cache-Control", `no-cache="Set-Cookie"`)
	if _, _, ok := cache.storability(qualified, http.StatusOK); ok {
		t.Error("a qualified no-cache was missed")
	}

	fine := http.Header{}
	fine.Set("Cache-Control", "public, max-age=60, stale-while-revalidate=30")
	if _, _, ok := cache.storability(fine, http.StatusOK); !ok {
		t.Error("an ordinary cacheable Cache-Control was refused")
	}
}

// Evicting to make room must not take a lock the caller already holds.
func TestCacheEvictionUnderMemoryPressure(t *testing.T) {
	cache := NewHttpCacheMiddleware(false, time.Minute, 32)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, key := range []string{"a", "b", "c"} {
			_ = cache.Set(t.Context(), key, &CacheEntry{
				Response:    []byte("0123456789012345"),
				ContentType: "text/plain",
			})
		}
		// Larger than the whole limit: it must be declined, not looped over.
		_ = cache.Set(t.Context(), "big", &CacheEntry{
			Response:    make([]byte, 1024),
			ContentType: "text/plain",
		})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Set blocked under memory pressure: eviction deadlocked or spun")
	}

	if cache.memoryUsed > cache.memoryLimit {
		t.Errorf("memoryUsed = %d, want it kept within the %d byte limit", cache.memoryUsed, cache.memoryLimit)
	}
}
