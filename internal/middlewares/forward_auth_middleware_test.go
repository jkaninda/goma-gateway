/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestForwardAuthForwardsAuthorization ensures the client's Authorization header
// is passed to the auth service, so a credential-reading auth endpoint (e.g.
// docker registry Basic auth) does not see an unauthenticated request.
func TestForwardAuthForwardsAuthorization(t *testing.T) {
	f := &ForwardAuth{}
	src := httptest.NewRequest(http.MethodGet, "https://registry.example.com/v2/acme/backend", nil)
	src.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	dest := httptest.NewRequest(http.MethodGet, "http://auth.internal/authz", nil)
	f.authCopyHeadersAndCookies(src, dest)

	if got := dest.Header.Get("Authorization"); got != "Basic dXNlcjpwYXNz" {
		t.Fatalf("Authorization not forwarded to auth service, got %q", got)
	}
	// The forwarded request context the auth endpoint relies on is also present.
	if dest.Header.Get("X-Forwarded-Method") != http.MethodGet {
		t.Fatalf("X-Forwarded-Method missing: %q", dest.Header.Get("X-Forwarded-Method"))
	}
}

// TestForwardAuthRelaysChallengeOnDeny ensures the auth service's
// WWW-Authenticate challenge is relayed to the client on a 401, and the auth
// status is mirrored — so docker login knows to present Basic credentials.
func TestForwardAuthRelaysChallengeOnDeny(t *testing.T) {
	const realm = `Basic realm="Miabi Registry"`
	for _, tc := range []struct {
		name       string
		authStatus int
		want       int
	}{
		{"401 challenge", http.StatusUnauthorized, http.StatusUnauthorized},
		{"403 forbidden", http.StatusForbidden, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("WWW-Authenticate", realm)
				w.WriteHeader(tc.authStatus)
			}))
			defer authSrv.Close()

			f := &ForwardAuth{AuthURL: authSrv.URL, Path: "/", Paths: []string{"/*"}}
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
			f.AuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("next handler must not run on a denied request")
			})).ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != realm {
				t.Fatalf("WWW-Authenticate not relayed, got %q", got)
			}
		})
	}
}

// TestForwardAuthNoAuthorizationHeader confirms nothing is set when the client
// sends no Authorization (avoids forwarding an empty header).
func TestForwardAuthNoAuthorizationHeader(t *testing.T) {
	f := &ForwardAuth{}
	src := httptest.NewRequest(http.MethodGet, "https://registry.example.com/v2/", nil)
	dest := httptest.NewRequest(http.MethodGet, "http://auth.internal/authz", nil)
	f.authCopyHeadersAndCookies(src, dest)

	if _, ok := dest.Header["Authorization"]; ok {
		t.Fatal("Authorization header should be absent when the client sends none")
	}
}
