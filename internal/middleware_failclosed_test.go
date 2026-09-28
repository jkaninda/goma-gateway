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
	"testing"

	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"github.com/jkaninda/njia"
)

func serveWithMiddleware(t *testing.T, mid Middleware, path string) int {
	t.Helper()
	route := &Route{Name: "test", Path: "/api"}
	rt, g := proxyGroup(route.Path)
	route.applyMiddlewareByType(mid, g)
	if err := registerPrefix(g, njia.MethodAny, "test", hit("proxied")); err != nil {
		t.Fatal(err)
	}
	return get(t, rt, http.MethodGet, path).Code
}

func TestInvalidAccessControlMiddlewareFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		mid  Middleware
	}{
		{"basic without users", Middleware{Type: BasicAuth, Rule: map[string]any{"realm": "x"}}},
		{"ldap without url", Middleware{Type: LDAPAuth, Rule: map[string]any{"baseDN": "dc=example"}}},
		{"jwt jwksUrl without issuer", Middleware{Type: JWTAuth, Rule: map[string]any{"jwksUrl": "https://sso.example.com/jwks", "audience": "a"}}},
		{"forwardAuth without authUrl", Middleware{Type: forwardAuth, Rule: map[string]any{}}},
		{"oidc without client", Middleware{Type: OIDC, Rule: map[string]any{"issuer": "https://sso.example.com"}}},
		{"accessPolicy with unknown action", Middleware{Type: accessPolicy, Rule: map[string]any{
			"action": "block", "sourceRanges": []any{"192.0.2.1"}}}},
		{"geoBlock without countries", Middleware{Type: geoBlock, Rule: map[string]any{"action": "DENY"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.mid.Name = "m"
			if got := serveWithMiddleware(t, tc.mid, "/api/resource"); got != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d: a misconfigured access-control middleware must not let requests through", got, http.StatusServiceUnavailable)
			}
		})
	}
}

func TestValidAuthMiddlewareStillApplies(t *testing.T) {
	mid := Middleware{Name: "m", Type: BasicAuth, Rule: map[string]any{
		"users": []any{map[string]any{"username": "admin", "password": "secret"}},
	}}
	if got := serveWithMiddleware(t, mid, "/api/resource"); got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", got, http.StatusUnauthorized)
	}
}

func TestAccessPolicyActionIsCaseInsensitive(t *testing.T) {
	// httptest requests come from 192.0.2.1.
	mid := Middleware{Name: "m", Type: accessPolicy, Rule: map[string]any{
		"action": "deny", "sourceRanges": []any{"192.0.2.1"},
	}}
	if got := serveWithMiddleware(t, mid, "/api/resource"); got != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: action \"deny\" must deny the listed sources", got, http.StatusForbidden)
	}
}

type headerPlugin struct{}

func (headerPlugin) Name() string             { return "tag" }
func (headerPlugin) Validate() error          { return nil }
func (headerPlugin) Configure(rule any) error { return nil }
func (headerPlugin) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Plugin", "ran")
		next.ServeHTTP(w, r)
	})
}

func TestRouteMiddlewareReferences(t *testing.T) {
	defined := []Middleware{
		{Name: "custom-auth", Type: "myAuthPlugin"}, // plugin type that did not load
		{Name: "tagger", Type: "tagPlugin"},
	}
	loaded := map[string]plugins.Middleware{"tagger": headerPlugin{}}
	for _, tc := range []struct {
		name       string
		middleware string
		want       int
	}{
		{"undefined middleware name", "jwt-auht", http.StatusServiceUnavailable},
		{"plugin type that failed to load", "custom-auth", http.StatusServiceUnavailable},
		{"loaded plugin", "tagger", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			route := &Route{Name: "test", Path: "/api", Middlewares: []string{tc.middleware}}
			rt, g := proxyGroup(route.Path)
			route.attachMiddlewares(g, defined, loaded)
			if err := registerPrefix(g, njia.MethodAny, "test", hit("proxied")); err != nil {
				t.Fatal(err)
			}
			if got := get(t, rt, http.MethodGet, "/api/x").Code; got != tc.want {
				t.Fatalf("status = %d, want %d", got, tc.want)
			}
		})
	}
}
