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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSession() *Session {
	return &Session{
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		IDToken:      testIDToken,
		Claims:       map[string]interface{}{claimSub: testSubject, claimEmail: testEmail},
		IssuedAt:     time.Now().Unix(),
		LastSeen:     time.Now().Unix(),
	}
}

// roundTrip saves a session and reads it back through a fresh request, the way
// a browser would.
func roundTrip(t *testing.T, store SessionStore, session *Session) (*Session, []*http.Cookie) {
	t.Helper()
	recorder := httptest.NewRecorder()
	if err := store.Save(recorder, httptest.NewRequest(http.MethodGet, "/", nil), session); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}
	cookies := recorder.Result().Cookies()

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	loaded, err := store.Load(request)
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	return loaded, cookies
}

func TestSessionStoreRoundTrip(t *testing.T) {
	for _, kind := range []string{SessionStoreCookie, SessionStoreMemory} {
		t.Run(kind, func(t *testing.T) {
			store, err := NewSessionStore(SessionOptions{Store: kind, Secret: testSecret})
			if err != nil {
				t.Fatalf("NewSessionStore() = %v, want nil", err)
			}

			loaded, _ := roundTrip(t, store, testSession())
			if loaded.AccessToken != "access-token" || loaded.IDToken != testIDToken {
				t.Errorf("session did not survive the round trip: %+v", loaded)
			}
			if loaded.Claims[claimEmail] != testEmail {
				t.Errorf("claims did not survive the round trip: %+v", loaded.Claims)
			}
		})
	}
}

// The tokens must not be readable by anything holding the cookie.
func TestCookieSessionIsSealed(t *testing.T) {
	store, err := NewSessionStore(SessionOptions{Store: SessionStoreCookie, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewSessionStore() = %v, want nil", err)
	}

	_, cookies := roundTrip(t, store, testSession())
	for _, cookie := range cookies {
		if strings.Contains(cookie.Value, "access-token") || strings.Contains(cookie.Value, testEmail) {
			t.Fatal("the session cookie carries readable token data")
		}
		if !cookie.HttpOnly {
			t.Error("the session cookie is not HttpOnly")
		}
		if cookie.SameSite != http.SameSiteLaxMode {
			t.Errorf("SameSite = %v, want Lax", cookie.SameSite)
		}
	}
}

// A cookie edited by its holder must not open, and must not be trusted.
func TestCookieSessionRejectsTampering(t *testing.T) {
	store, err := NewSessionStore(SessionOptions{Store: SessionStoreCookie, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewSessionStore() = %v, want nil", err)
	}
	_, cookies := roundTrip(t, store, testSession())

	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	value := []byte(cookies[0].Value)
	value[len(value)/2] ^= 0x01
	tampered.AddCookie(&http.Cookie{Name: cookies[0].Name, Value: string(value)})

	if _, err := store.Load(tampered); err == nil {
		t.Error("Load() accepted a tampered session cookie")
	}
}

// A session sealed with one secret must not open with another, so rotating the
// secret ends every session rather than letting them drift.
func TestCookieSessionIsBoundToTheSecret(t *testing.T) {
	original, _ := NewSessionStore(SessionOptions{Store: SessionStoreCookie, Secret: testSecret})
	other, _ := NewSessionStore(SessionOptions{Store: SessionStoreCookie, Secret: "a-different-secret"})

	recorder := httptest.NewRecorder()
	if err := original.Save(recorder, httptest.NewRequest(http.MethodGet, "/", nil), testSession()); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}
	if _, err := other.Load(request); err == nil {
		t.Error("Load() accepted a session sealed with a different secret")
	}
}

// A session too large for one cookie is split, and reassembled on the way back.
func TestCookieSessionChunking(t *testing.T) {
	store, err := NewSessionStore(SessionOptions{Store: SessionStoreCookie, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewSessionStore() = %v, want nil", err)
	}

	// A groups claim large enough to exceed a single cookie.
	groups := make([]interface{}, 0, 100)
	for index := 0; index < 100; index++ {
		groups = append(groups, "group-with-a-fairly-long-name-"+strings.Repeat("x", 20))
	}
	session := testSession()
	session.Claims = map[string]interface{}{claimSub: testSubject, claimGroups: groups}

	loaded, cookies := roundTrip(t, store, session)
	if len(cookies) < 2 {
		t.Fatalf("a %d-group session fit in %d cookie(s), expected it to be chunked", len(groups), len(cookies))
	}
	for _, cookie := range cookies {
		if len(cookie.Value) > maxCookieChunkBytes {
			t.Errorf("chunk %q is %d bytes, over the %d limit", cookie.Name, len(cookie.Value), maxCookieChunkBytes)
		}
	}
	restored, ok := loaded.Claims[claimGroups].([]interface{})
	if !ok || len(restored) != len(groups) {
		t.Errorf("the chunked session lost claims: got %d groups, want %d", len(restored), len(groups))
	}
}

// A session that cannot be read back must not be written: the browser would be
// left holding cookies that never open again.
func TestCookieSessionRefusesOversizedSessions(t *testing.T) {
	store, err := NewSessionStore(SessionOptions{Store: SessionStoreCookie, Secret: testSecret})
	if err != nil {
		t.Fatalf("NewSessionStore() = %v, want nil", err)
	}

	session := testSession()
	session.Claims = map[string]interface{}{claimGroups: strings.Repeat("x", maxCookieChunks*maxCookieChunkBytes)}

	err = store.Save(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), session)
	if err == nil {
		t.Fatal("Save() = nil, want an error for a session too large for cookies")
	}
	if !strings.Contains(err.Error(), "redis") {
		t.Errorf("Save() error = %q, want it to point at a server-side store", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	tests := []struct {
		name        string
		session     Session
		ttl         time.Duration
		idleTimeout time.Duration
		want        bool
	}{
		{testFreshSession, Session{IssuedAt: time.Now().Unix(), LastSeen: time.Now().Unix()}, time.Hour, time.Hour, false},
		{"past the absolute ttl",
			Session{IssuedAt: time.Now().Add(-2 * time.Hour).Unix(), LastSeen: time.Now().Unix()}, time.Hour, 0, true},
		{"idle too long",
			Session{IssuedAt: time.Now().Unix(), LastSeen: time.Now().Add(-2 * time.Hour).Unix()}, 0, time.Hour, true},
		{"idle but no idle timeout configured",
			Session{IssuedAt: time.Now().Unix(), LastSeen: time.Now().Add(-2 * time.Hour).Unix()}, time.Hour, 0, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.session.expired(test.ttl, test.idleTimeout); got != test.want {
				t.Errorf("expired() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestExpiredSessionIsNotLoaded(t *testing.T) {
	store, err := NewSessionStore(SessionOptions{
		Store: SessionStoreCookie, Secret: testSecret, TTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSessionStore() = %v, want nil", err)
	}

	session := testSession()
	session.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()

	recorder := httptest.NewRecorder()
	if err := store.Save(recorder, httptest.NewRequest(http.MethodGet, "/", nil), session); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, cookie := range recorder.Result().Cookies() {
		request.AddCookie(cookie)
	}

	if _, err := store.Load(request); !errors.Is(err, errNoSession) {
		t.Errorf("Load() = %v, want errNoSession", err)
	}
}

func TestSessionStoreClear(t *testing.T) {
	for _, kind := range []string{SessionStoreCookie, SessionStoreMemory} {
		t.Run(kind, func(t *testing.T) {
			store, _ := NewSessionStore(SessionOptions{Store: kind, Secret: testSecret})
			_, cookies := roundTrip(t, store, testSession())

			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range cookies {
				request.AddCookie(cookie)
			}
			recorder := httptest.NewRecorder()
			store.Clear(recorder, request)

			cleared := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range recorder.Result().Cookies() {
				cleared.AddCookie(cookie)
			}
			if _, err := store.Load(cleared); err == nil {
				t.Error("Load() still returned a session after Clear()")
			}
		})
	}
}

func TestUnknownSessionStore(t *testing.T) {
	if _, err := NewSessionStore(SessionOptions{Store: "database", Secret: testSecret}); err == nil {
		t.Error("NewSessionStore() = nil error for an unknown store")
	}
	// Redis is only usable once the gateway has a Redis connection.
	if _, err := NewSessionStore(SessionOptions{Store: SessionStoreRedis, Secret: testSecret}); err == nil {
		t.Error("NewSessionStore() = nil error for redis without a Redis client")
	}
}

func TestDiscovery(t *testing.T) {
	var requests int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != discoveryPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requests++
		_ = json.NewEncoder(w).Encode(ProviderMetadata{
			Issuer:                server.URL,
			AuthorizationEndpoint: server.URL + "/authorize",
			TokenEndpoint:         server.URL + "/token",
			UserInfoEndpoint:      server.URL + "/userinfo",
			JwksURI:               server.URL + "/jwks",
			EndSessionEndpoint:    server.URL + "/end-session",
		})
	}))
	defer server.Close()
	resetDiscoveryCache()

	metadata, err := Discover(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Discover() = %v, want nil", err)
	}
	if metadata.JwksURI != server.URL+"/jwks" {
		t.Errorf("JwksURI = %q, want the discovered endpoint", metadata.JwksURI)
	}

	// The document is cached, not fetched per request.
	if _, err := Discover(context.Background(), server.URL); err != nil {
		t.Fatalf("Discover() = %v, want nil", err)
	}
	if requests != 1 {
		t.Errorf("the discovery document was fetched %d times, want 1", requests)
	}

	// The middleware fills its endpoints from it.
	config := testConfig()
	config.Issuer = server.URL
	config.Endpoint = OauthEndpoint{}
	oidc := newTestOIDC(t, config)

	endpoint, endSession, err := oidc.endpoints(context.Background())
	if err != nil {
		t.Fatalf("endpoints() = %v, want nil", err)
	}
	if endpoint.AuthURL != server.URL+"/authorize" || endpoint.JwksURL != server.URL+"/jwks" {
		t.Errorf("endpoints() = %+v, want the discovered endpoints", endpoint)
	}
	if endSession != server.URL+"/end-session" {
		t.Errorf("end session endpoint = %q, want the discovered one", endSession)
	}
}

// A document describing a different issuer than the one configured must be
// refused: it would point verification at the wrong provider.
func TestDiscoveryRejectsIssuerMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(ProviderMetadata{
			Issuer:                "https://another-issuer.example.com",
			AuthorizationEndpoint: "https://another-issuer.example.com/authorize",
			TokenEndpoint:         "https://another-issuer.example.com/token",
		})
	}))
	defer server.Close()
	resetDiscoveryCache()

	if _, err := Discover(context.Background(), server.URL); err == nil {
		t.Error("Discover() = nil error, want the issuer mismatch to be refused")
	}
}

// Explicit endpoints must be honoured over anything discovery would supply.
func TestExplicitEndpointsWin(t *testing.T) {
	resetDiscoveryCache()

	config := testConfig()
	config.Issuer = "https://unreachable.invalid"
	config.Endpoint.JwksURL = "https://configured.example.com/jwks"
	oidc := newTestOIDC(t, config)

	endpoint, _, err := oidc.endpoints(context.Background())
	if err != nil {
		t.Fatalf("endpoints() = %v, want nil", err)
	}
	if endpoint.AuthURL != testAuthURL || endpoint.JwksURL != "https://configured.example.com/jwks" {
		t.Errorf("endpoints() = %+v, want the configured endpoints", endpoint)
	}
}
