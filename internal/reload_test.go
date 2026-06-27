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

	"github.com/gorilla/mux"
)

// fakeRouter is a no-op Router used to exercise the reload handler without
// booting the full gateway.
type fakeRouter struct{ updated int }

func (f *fakeRouter) AddRoute(*Route) error                        { return nil }
func (f *fakeRouter) AddRoutes() error                             { return nil }
func (f *fakeRouter) Mux() http.Handler                            { return nil }
func (f *fakeRouter) UpdateHandler(*Goma)                          { f.updated++ }
func (f *fakeRouter) ServeHTTP(http.ResponseWriter, *http.Request) {}

func newReloadMux(t *testing.T, cfg ReloadConfig) *mux.Router {
	t.Helper()
	// reloadToken() prefers GOMA_RELOAD_TOKEN; drive it through the env so the
	// helper resolves the same token regardless of any ambient value.
	t.Setenv("GOMA_RELOAD_TOKEN", cfg.Token)
	g := &Goma{gateway: &Gateway{Reload: cfg}}
	m := mux.NewRouter()
	g.registerReloadHandler(m, &fakeRouter{})
	return m
}

func TestReloadHandlerRejectsMissingAndBadToken(t *testing.T) {
	m := newReloadMux(t, ReloadConfig{Enabled: true, Token: "secret"})

	for _, tc := range []struct {
		name, auth string
	}{
		{"no header", ""},
		{"wrong scheme", "Token secret"},
		{"wrong token", "Bearer nope"},
	} {
		req := httptest.NewRequest(http.MethodPost, "/gateway/reload", nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", tc.auth)
		}
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", tc.name, rec.Code)
		}
	}
}

func TestReloadHandlerRejectsNonPost(t *testing.T) {
	m := newReloadMux(t, ReloadConfig{Enabled: true, Token: "secret"})
	req := httptest.NewRequest(http.MethodGet, "/gateway/reload", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestReloadHandlerNotRegisteredWhenDisabled(t *testing.T) {
	for _, cfg := range []ReloadConfig{
		{Enabled: false, Token: "secret"},
		{Enabled: true, Token: ""},
	} {
		m := newReloadMux(t, cfg)
		req := httptest.NewRequest(http.MethodPost, "/gateway/reload", nil)
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		m.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("cfg %+v: expected 404 (unregistered), got %d", cfg, rec.Code)
		}
	}
}

func TestReloadHandlerCustomPath(t *testing.T) {
	m := newReloadMux(t, ReloadConfig{Enabled: true, Token: "secret", Path: "/-/reload"})
	req := httptest.NewRequest(http.MethodPost, "/-/reload", nil)
	// No auth → still routed (401), proving the custom path is registered.
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on custom path, got %d", rec.Code)
	}
}

func TestValidReloadToken(t *testing.T) {
	mk := func(auth string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/reload", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		return r
	}
	if !validReloadToken(mk("Bearer secret"), "secret") {
		t.Fatal("expected valid")
	}
	if validReloadToken(mk("Bearer secret "), "secret") == false {
		// trailing space is trimmed, still valid
		t.Fatal("expected trimmed token to be valid")
	}
	if validReloadToken(mk(""), "secret") {
		t.Fatal("expected missing header invalid")
	}
	if validReloadToken(mk("Bearer other"), "secret") {
		t.Fatal("expected wrong token invalid")
	}
}
