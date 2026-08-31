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

	"github.com/jkaninda/goma-gateway/internal/middlewares"
)

// The audit's proof of concept: an auth rule guarding a multi-segment path was
// bypassed by inserting one extra slash, a dot segment, or an encoded one,
// because the gateway matched the raw path while the backend resolved it. Every
// variant below is a path a common upstream — nginx, Apache, Tomcat, Express,
// Go's own ServeMux — collapses back to the guarded path.
func TestCanonicalizePathClosesTheAuthBypass(t *testing.T) {
	const guarded = "/api/v1/users"

	tests := []struct {
		request      string
		wantStatus   int
		wantSeenPath string
	}{
		{"/api/v1/users", http.StatusUnauthorized, ""},
		{"/api/v1//users", http.StatusUnauthorized, ""},
		{"/api/v1/./users", http.StatusUnauthorized, ""},
		{"/api/v1/x/../users", http.StatusUnauthorized, ""},
		{"/api/v1/x/..%2fusers", http.StatusBadRequest, ""},
		{"/api/v1/x/..%2Fusers", http.StatusBadRequest, ""},
		{"/api/v1/%2e%2e/users", http.StatusBadRequest, ""},
		// Not the guarded resource, and not rewritten into it either.
		{"/api/v1/other", http.StatusOK, "/api/v1/other"},
		{"/api/v1//other", http.StatusOK, "/api/v1/other"},
	}

	for _, tt := range tests {
		t.Run(tt.request, func(t *testing.T) {
			var seenPath string
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seenPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			})

			// The guard the operator configured, matching the way every auth
			// middleware does.
			guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if matched, _ := middlewares.IsPathMatching(r.URL.Path, "", []string{guarded}); matched {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				backend.ServeHTTP(w, r)
			})

			rec := httptest.NewRecorder()
			canonicalizePath(guard).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.request, nil))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (backend saw %q)", rec.Code, tt.wantStatus, seenPath)
			}
			if tt.wantSeenPath != "" && seenPath != tt.wantSeenPath {
				t.Errorf("backend saw %q, want %q", seenPath, tt.wantSeenPath)
			}
		})
	}
}

func TestCleanURLPathPreservesTrailingSlash(t *testing.T) {
	cases := map[string]string{
		"/a/b":      "/a/b",
		"/a//b":     "/a/b",
		"/a/./b":    "/a/b",
		"/a/c/../b": "/a/b",
		"/a/b/":     "/a/b/",
		"/a//b//":   "/a/b/",
		"/":         "/",
		"//":        "/",
		"":          "/",
	}
	for in, want := range cases {
		if got := cleanURLPath(in); got != want {
			t.Errorf("cleanURLPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// An encoded dot inside an ordinary filename is not a traversal and must still
// be served.
func TestHasEncodedSeparator(t *testing.T) {
	cases := map[string]bool{
		"/api/v1/users":           false,
		"/api/v1/x/..%2fusers":    true,
		"/api/v1/x/..%5cusers":    true,
		"/api/v1/%2e%2e/users":    true,
		"/api/v1/%2E%2E/users":    true,
		"/files/report%2ev1.json": false,
		"/files/a%20b":            false,
	}
	for in, want := range cases {
		if got := hasEncodedSeparator(in); got != want {
			t.Errorf("hasEncodedSeparator(%q) = %v, want %v", in, got, want)
		}
	}
}
