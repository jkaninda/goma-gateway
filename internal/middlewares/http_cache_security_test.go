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
	"strings"
	"testing"
	"time"
)

const headerAuthorize = "Authorization"

// A cached response must never be handed to a caller other than the one it was
// produced for.
func TestCacheBypassesCredentialedRequests(t *testing.T) {
	var upstreamCalls int
	cache := HttpCacheConfig{
		Path:  "/",
		Paths: []string{testAllPaths},
		Name:  "test",
		Cache: NewHttpCacheMiddleware(false, time.Minute, 1<<20),
		TTL:   time.Minute,
	}

	handler := cache.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		_, _ = w.Write([]byte("body for " + r.Header.Get(headerAuthorize)))
	}))

	// An anonymous request populates the cache.
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/data", nil))

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/data", nil))
	if upstreamCalls != 1 {
		t.Errorf("anonymous requests hit the upstream %d times, want 1 (the second should be cached)", upstreamCalls)
	}

	// A credentialed request must neither read that entry nor leave one behind.
	authenticated := httptest.NewRequest(http.MethodGet, "/data", nil)
	authenticated.Header.Set(headerAuthorize, "Bearer alice")
	third := httptest.NewRecorder()
	handler.ServeHTTP(third, authenticated)

	if upstreamCalls != 2 {
		t.Errorf("the credentialed request was served from cache, upstream calls = %d, want 2", upstreamCalls)
	}
	if body := third.Body.String(); !strings.Contains(body, "Bearer alice") {
		t.Errorf("body = %q, want the response produced for this caller", body)
	}
	if got := third.Header().Get("Cache-Control"); strings.Contains(got, "public") {
		t.Errorf("Cache-Control = %q, want a credentialed response not marked public", got)
	}
}

func TestCacheDoesNotStorePerCallerResponses(t *testing.T) {
	tests := map[string][2]string{
		"sets a cookie":        {"Set-Cookie", "session=abc"},
		"marked private":       {"Cache-Control", "private, max-age=60"},
		"marked no-store":      {"Cache-Control", "no-store"},
		"varies on everything": {"Vary", "*"},
		"auth challenge":       {"WWW-Authenticate", `Bearer realm="x"`},
	}
	cache := HttpCacheConfig{Name: "test"}
	for name, pair := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			header.Set(pair[0], pair[1])
			if _, _, storable := cache.storability(header, http.StatusOK); storable {
				t.Errorf("storability(%v) said the response may be cached", header)
			}
		})
	}

	encodingVary := http.Header{}
	encodingVary.Set("Vary", "Accept-Encoding")
	if fields, _, storable := cache.storability(encodingVary, http.StatusOK); !storable || len(fields) != 0 {
		t.Errorf("a response varying only on Accept-Encoding gave fields=%v storable=%v, want none and true", fields, storable)
	}
}

// The gateway must not hand a gzip body to a client that asked for none.
func TestCacheKeySeparatesHostsAndEncodings(t *testing.T) {
	cache := HttpCacheConfig{Name: "test"}

	plain := httptest.NewRequest(http.MethodGet, "http://a.example.com/data", nil)
	gzipped := httptest.NewRequest(http.MethodGet, "http://a.example.com/data", nil)
	gzipped.Header.Set("Accept-Encoding", "gzip, deflate")
	otherHost := httptest.NewRequest(http.MethodGet, "http://b.example.com/data", nil)

	if cache.generateCacheKey(plain) == cache.generateCacheKey(gzipped) {
		t.Error("requests with different Accept-Encoding share a cache key")
	}
	if cache.generateCacheKey(plain) == cache.generateCacheKey(otherHost) {
		t.Error("requests for different hosts share a cache key")
	}
}
