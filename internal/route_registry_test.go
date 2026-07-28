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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkaninda/njia"
)

// proxyGroup builds the router and per-route group the gateway builds for a
// configured route path.
func proxyGroup(path string) (*njia.Router, *njia.Group) {
	rt := newProxyRouter(false)
	return rt, rt.Group(groupPrefix(path))
}

func hit(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, body)
	})
}

func get(t *testing.T, rt *njia.Router, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestGroupPrefix(t *testing.T) {
	for _, tc := range []struct{ path, want string }{
		{"/api/v1", "/api/v1"},
		{"/api/v1/", "/api/v1"},
		{"/", ""},
		{"", ""},
		{"api/v1", "/api/v1"},
	} {
		if got := groupPrefix(tc.path); got != tc.want {
			t.Errorf("groupPrefix(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// A route's handler has to answer every verb, because which methods a route
// allows is enforced against route.Methods further in, not by the router.
func TestRegisterPrefixServesArbitraryVerbs(t *testing.T) {
	rt, g := proxyGroup("/api/v1")
	if err := registerPrefix(g, njia.MethodAny, "test", hit("proxied")); err != nil {
		t.Fatalf("registerPrefix: %v", err)
	}

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1"},
		{http.MethodPost, "/api/v1/books"},
		{"PROPFIND", "/api/v1/deep/nested/path"},
		{"X-CUSTOM-VERB", "/api/v1/x"},
	} {
		rec := get(t, rt, tc.method, tc.path)
		if rec.Code != http.StatusOK || rec.Body.String() != "proxied" {
			t.Errorf("%s %s: got %d %q, want 200 %q",
				tc.method, tc.path, rec.Code, rec.Body.String(), "proxied")
		}
	}
}

// Registering at the root covers everything.
func TestRegisterPrefixAtRoot(t *testing.T) {
	rt, g := proxyGroup("/")
	if err := registerPrefix(g, njia.MethodAny, "root", hit("root")); err != nil {
		t.Fatalf("registerPrefix: %v", err)
	}
	for _, path := range []string{"/", "/anything", "/deep/nested"} {
		if rec := get(t, rt, http.MethodGet, path); rec.Body.String() != "root" {
			t.Errorf("%s = %q, want %q", path, rec.Body.String(), "root")
		}
	}
}

// Prefix matching is on segment boundaries, so a sibling path that merely
// shares a string prefix is not swallowed.
func TestRegisterPrefixIsSegmentBounded(t *testing.T) {
	rt, g := proxyGroup("/api")
	if err := registerPrefix(g, njia.MethodAny, "test", hit("proxied")); err != nil {
		t.Fatalf("registerPrefix: %v", err)
	}
	if rec := get(t, rt, http.MethodGet, "/apiary"); rec.Code != http.StatusNotFound {
		t.Fatalf("/apiary = %d, want 404", rec.Code)
	}
}

// Two routes configured with the same path used to be resolved by gorilla in
// favour of the first, so loading such a configuration must not start failing.
func TestRegisterPrefixToleratesDuplicatePath(t *testing.T) {
	rt := newProxyRouter(false)
	first := rt.Group(groupPrefix("/dup"))
	second := rt.Group(groupPrefix("/dup"))

	if err := registerPrefix(first, njia.MethodAny, "a", hit("first")); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := registerPrefix(second, njia.MethodAny, "b", hit("second")); err != nil {
		t.Fatalf("duplicate path should be tolerated, got: %v", err)
	}
	if rec := get(t, rt, http.MethodGet, "/dup"); rec.Body.String() != "first" {
		t.Fatalf("body = %q, want %q (first registration wins)", rec.Body.String(), "first")
	}
}

// Middleware must wrap the route's handler outermost-first in the order it was
// added, which is the order the gateway's middleware appliers rely on.
func TestGroupMiddlewareOrder(t *testing.T) {
	var order []string
	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	rt, g := proxyGroup("/api")
	g.Use(mark("first"))
	g.Use(mark("second"), mark("third"))
	if err := registerPrefix(g, njia.MethodAny, "test", http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) { order = append(order, "handler") },
	)); err != nil {
		t.Fatalf("registerPrefix: %v", err)
	}

	get(t, rt, http.MethodGet, "/api/x")
	if got := strings.Join(order, ","); got != "first,second,third,handler" {
		t.Fatalf("order = %q, want %q", got, "first,second,third,handler")
	}
}

// Middleware added after the handler was registered still wraps it. The
// gateway's appliers run in that order, so this is the property that keeps
// authentication attached.
func TestGroupMiddlewareAppliesWhenAddedAfterRegistration(t *testing.T) {
	var ran bool
	rt, g := proxyGroup("/api")
	if err := registerPrefix(g, njia.MethodAny, "test", hit("ok")); err != nil {
		t.Fatalf("registerPrefix: %v", err)
	}
	g.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ran = true
			next.ServeHTTP(w, r)
		})
	})

	get(t, rt, http.MethodGet, "/api/x")
	if !ran {
		t.Fatal("middleware added after registration did not wrap the handler")
	}
}

// A route a middleware registers on the group — an OAuth callback, say — is
// wrapped by that same middleware and outranks the route's catch-all.
func TestGroupExtraRouteSharesMiddlewareAndWins(t *testing.T) {
	var wrapped int
	rt, g := proxyGroup("/api")
	g.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wrapped++
			next.ServeHTTP(w, r)
		})
	})
	if err := g.Handle(http.MethodGet, "/callback", hit("callback")); err != nil {
		t.Fatalf("callback: %v", err)
	}
	if err := registerPrefix(g, njia.MethodAny, "test", hit("proxied")); err != nil {
		t.Fatalf("registerPrefix: %v", err)
	}

	if rec := get(t, rt, http.MethodGet, "/api/callback"); rec.Body.String() != "callback" {
		t.Errorf("/api/callback = %q, want %q", rec.Body.String(), "callback")
	}
	if rec := get(t, rt, http.MethodGet, "/api/other"); rec.Body.String() != "proxied" {
		t.Errorf("/api/other = %q, want %q", rec.Body.String(), "proxied")
	}
	if wrapped != 2 {
		t.Errorf("middleware ran %d times, want 2 (both routes wrapped)", wrapped)
	}
}

// Priority lets a catch-all deliberately shadow a more specific route, which is
// the behaviour the gateway documents for route priority.
func TestRoutePriorityShadowsMoreSpecific(t *testing.T) {
	rt := newProxyRouter(false)
	specific := rt.Group(groupPrefix("/api/v1"))
	catchAll := rt.Group(groupPrefix("/api"))

	if err := registerPrefix(specific, njia.MethodAny, "specific", hit("specific")); err != nil {
		t.Fatalf("specific: %v", err)
	}
	if err := registerPrefix(catchAll, njia.MethodAny, "catchall", hit("catchall"),
		njia.WithPriority(-1)); err != nil {
		t.Fatalf("catchall: %v", err)
	}

	if rec := get(t, rt, http.MethodGet, "/api/v1/books"); rec.Body.String() != "catchall" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "catchall")
	}
}

// Without priority the longer path wins, which is the gateway's default.
func TestRouteDefaultPrefersLongestPath(t *testing.T) {
	rt := newProxyRouter(false)
	catchAll := rt.Group(groupPrefix("/api"))
	specific := rt.Group(groupPrefix("/api/v1"))

	if err := registerPrefix(catchAll, njia.MethodAny, "catchall", hit("catchall")); err != nil {
		t.Fatalf("catchall: %v", err)
	}
	if err := registerPrefix(specific, njia.MethodAny, "specific", hit("specific")); err != nil {
		t.Fatalf("specific: %v", err)
	}

	if rec := get(t, rt, http.MethodGet, "/api/v1/books"); rec.Body.String() != "specific" {
		t.Fatalf("body = %q, want %q", rec.Body.String(), "specific")
	}
}
