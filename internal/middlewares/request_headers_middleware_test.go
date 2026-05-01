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
)

func TestRequestHeaders_SetAndRemove(t *testing.T) {
	rh := &RequestHeaders{
		SetHeaders: map[string]string{
			"X-Forwarded-Proto": "https",
			"X-Strip":           "", // empty value deletes
		},
		RemoveHeaders: []string{"Authorization"},
	}

	var seen http.Header
	handler := rh.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer xyz")
	req.Header.Set("X-Strip", "leak")
	req.Header.Set("Keep", "yes")

	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := seen.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("expected SetHeaders to add X-Forwarded-Proto=https, got %q", got)
	}
	if got := seen.Get("Authorization"); got != "" {
		t.Fatalf("expected RemoveHeaders to drop Authorization, got %q", got)
	}
	if got := seen.Get("X-Strip"); got != "" {
		t.Fatalf("expected empty SetHeaders value to delete X-Strip, got %q", got)
	}
	if got := seen.Get("Keep"); got != "yes" {
		t.Fatalf("expected unrelated headers to pass through, got %q", got)
	}
}

func TestRequestHeaders_PathScoping(t *testing.T) {
	rh := &RequestHeaders{
		Paths:      []string{"/api/*"},
		SetHeaders: map[string]string{"X-Touched": "yes"},
	}

	var seen http.Header
	handler := rh.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))

	matched := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	handler.ServeHTTP(httptest.NewRecorder(), matched)
	if seen.Get("X-Touched") != "yes" {
		t.Fatalf("expected match on /api/users")
	}

	other := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(httptest.NewRecorder(), other)
	if seen.Get("X-Touched") != "" {
		t.Fatalf("expected non-match on /health, got %q", seen.Get("X-Touched"))
	}
}

func TestRequestHeaders_RemoveAppliesBeforeSet(t *testing.T) {
	rh := &RequestHeaders{
		RemoveHeaders: []string{"X-Re-Add"},
		SetHeaders:    map[string]string{"X-Re-Add": "fresh"},
	}

	var seen http.Header
	handler := rh.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Re-Add", "stale")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if got := seen.Get("X-Re-Add"); got != "fresh" {
		t.Fatalf("expected SetHeaders to override after RemoveHeaders, got %q", got)
	}
}
