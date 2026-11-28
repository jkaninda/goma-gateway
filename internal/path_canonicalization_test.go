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
	"gopkg.in/yaml.v3"
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

			guard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if matched, _ := middlewares.IsPathMatching(r.URL.Path, "", []string{guarded}); matched {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				backend.ServeHTTP(w, r)
			})

			rec := httptest.NewRecorder()
			canonicalizePath(guard, false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.request, nil))

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

func TestCanonicalizePathRefusesPathParameters(t *testing.T) {
	guards := [][]string{{"/admin"}, {"/admin/*"}, {"^/admin(/.*)?$"}}

	tests := []struct {
		request    string
		wantStatus int
	}{
		{"/admin/secret.txt", http.StatusUnauthorized},
		{"/public/note.txt", http.StatusOK},
		{"/x/..;/admin/secret.txt", http.StatusBadRequest},
		{"/x/..;a=b/admin/secret.txt", http.StatusBadRequest},
		{"/x/..;jsessionid=1/admin/secret.txt", http.StatusBadRequest},
		{"/public/..;/admin/secret.txt", http.StatusBadRequest},
		{"/x/.;/../admin/secret.txt", http.StatusBadRequest},
		{"/;/admin/secret.txt", http.StatusBadRequest},
		{"/admin;/secret.txt", http.StatusBadRequest},
		{"/admin;x=1/secret.txt", http.StatusBadRequest},
		{"/x/..%3b/admin/secret.txt", http.StatusBadRequest},
		{"/x/..%3B/admin/secret.txt", http.StatusBadRequest},
		{"/app/page;jsessionid=ABC", http.StatusBadRequest},
	}

	for _, guard := range guards {
		for _, tt := range tests {
			t.Run(guard[0]+" "+tt.request, func(t *testing.T) {
				rec := serveGuarded(t, guard, tt.request, false)
				if rec.Code != tt.wantStatus {
					t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
				}
			})
		}
	}
}

func TestCanonicalizePathResolvesParameterDotSegments(t *testing.T) {
	guards := [][]string{{"/admin"}, {"/admin/*"}, {"^/admin(/.*)?$"}}

	tests := []struct {
		request      string
		wantStatus   int
		wantSeenPath string
	}{
		{"/app/page;jsessionid=ABC", http.StatusOK, "/app/page;jsessionid=ABC"},
		{"/app;v=1/page", http.StatusOK, "/app;v=1/page"},
		{"/admin/secret.txt", http.StatusUnauthorized, ""},
		{"/x/..;/admin/secret.txt", http.StatusUnauthorized, ""},
		{"/x/..;a=b/admin/secret.txt", http.StatusUnauthorized, ""},
		{"/x/..;jsessionid=1/admin/secret.txt", http.StatusUnauthorized, ""},
		{"/public/..;/admin/secret.txt", http.StatusUnauthorized, ""},
		{"/x/.;/../admin/secret.txt", http.StatusUnauthorized, ""},
		{"/;/admin/secret.txt", http.StatusUnauthorized, ""},
		{"/..;/admin/secret.txt", http.StatusUnauthorized, ""},
		{"/x/..%3b/admin/secret.txt", http.StatusUnauthorized, ""},
		// Resolved, but not into the guarded path.
		{"/x/y/..;/public/note.txt", http.StatusOK, "/x/public/note.txt"},
	}

	for _, guard := range guards {
		for _, tt := range tests {
			t.Run(guard[0]+" "+tt.request, func(t *testing.T) {
				var seenPath string
				rec := serveGuardedSeeing(t, guard, tt.request, true, &seenPath)
				if rec.Code != tt.wantStatus {
					t.Fatalf("status = %d, want %d (backend saw %q)", rec.Code, tt.wantStatus, seenPath)
				}
				if tt.wantSeenPath != "" && seenPath != tt.wantSeenPath {
					t.Errorf("backend saw %q, want %q", seenPath, tt.wantSeenPath)
				}
			})
		}
	}
}

func TestResolveParameterDotSegments(t *testing.T) {
	cases := map[string]string{
		"/api/v1/users":          "/api/v1/users",
		"/app/page;jsessionid=1": "/app/page;jsessionid=1",
		"/app;v=1/page":          "/app;v=1/page",
		"/x/..;/admin":           "/x/../admin",
		"/x/..;a=b/admin":        "/x/../admin",
		"/x/.;/admin":            "/x/./admin",
		"/;/admin":               "//admin",
		"/x/...;/admin":          "/x/...;/admin",
	}
	for in, want := range cases {
		if got := resolveParameterDotSegments(in); got != want {
			t.Errorf("resolveParameterDotSegments(%q) = %q, want %q", in, got, want)
		}
	}
}

func serveGuarded(t *testing.T, guard []string, request string, allowPathParameters bool) *httptest.ResponseRecorder {
	var seen string
	return serveGuardedSeeing(t, guard, request, allowPathParameters, &seen)
}

// serveGuardedSeeing runs request through canonicalizePath and a guard that
// matches the way the auth and access middlewares do on a route rooted at "/".
func serveGuardedSeeing(t *testing.T, guard []string, request string, allowPathParameters bool, seenPath *string) *httptest.ResponseRecorder {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if matched, _ := middlewares.IsPathMatching(r.URL.Path, "/", guard); matched {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		*seenPath = r.URL.EscapedPath()
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	canonicalizePath(handler, allowPathParameters).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, request, nil))
	return rec
}

func TestAllowPathParametersDefaultsToTrue(t *testing.T) {
	var g Gateway
	if err := yaml.Unmarshal([]byte("routes: []\n"), &g); err != nil {
		t.Fatal(err)
	}
	if !g.AllowPathParameters {
		t.Error("allowPathParameters should default to true")
	}

	g = Gateway{}
	if err := yaml.Unmarshal([]byte("allowPathParameters: false\n"), &g); err != nil {
		t.Fatal(err)
	}
	if g.AllowPathParameters {
		t.Error("allowPathParameters: false should be honoured")
	}
}
