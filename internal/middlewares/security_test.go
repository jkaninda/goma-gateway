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
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jkaninda/goma-gateway/internal/config"
)

// Fixtures for the forwarded-header tests.
const (
	clientAddr      = "203.0.113.9:5555"
	clientIP        = "203.0.113.9"
	proxyAddr       = "10.1.2.3:5555"
	proxyCIDR       = "10.0.0.0/8"
	spoofedIP       = "1.2.3.4"
	realClientIP    = "198.51.100.7"
	forwardedProto  = "X-Forwarded-Proto"
	forwardedFor    = "X-Forwarded-For"
	headerAuthorize = "Authorization"
)

// tlsConnectionState stands in for a real TLS handshake.
var tlsConnectionState = tls.ConnectionState{HandshakeComplete: true}

// withTrustedProxies installs a proxy configuration for the duration of a test.
func withTrustedProxies(t *testing.T, enabled bool, proxies ...string) {
	t.Helper()
	previous := TrustedProxyConfig
	t.Cleanup(func() { TrustedProxyConfig = previous })

	proxyConfig := &config.ProxyConfig{Enabled: enabled, TrustedProxies: proxies}
	initialized, err := proxyConfig.Init()
	if enabled && len(proxies) > 0 && err != nil {
		t.Fatalf("failed to initialize the proxy configuration: %v", err)
	}
	TrustedProxyConfig = initialized
}

func forwardedRequest(remoteAddr string, headers map[string]string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = remoteAddr
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

// A client that is not a trusted proxy must not be able to choose the address
// that access policies, geo blocking and rate limits are applied to.
func TestRealIPIgnoresUntrustedForwardedHeaders(t *testing.T) {
	tests := []struct {
		name     string
		enabled  bool
		proxies  []string
		remote   string
		headers  map[string]string
		wantAddr string
	}{
		{
			name:     "forwarding disabled",
			remote:   clientAddr,
			headers:  map[string]string{forwardedFor: spoofedIP},
			wantAddr: clientIP,
		},
		{
			name:     "enabled with no trusted proxies configured",
			enabled:  true,
			remote:   clientAddr,
			headers:  map[string]string{forwardedFor: spoofedIP},
			wantAddr: clientIP,
		},
		{
			name:     "request did not come from a trusted proxy",
			enabled:  true,
			proxies:  []string{proxyCIDR},
			remote:   clientAddr,
			headers:  map[string]string{forwardedFor: spoofedIP},
			wantAddr: clientIP,
		},
		{
			name:     "trusted proxy is believed",
			enabled:  true,
			proxies:  []string{proxyCIDR},
			remote:   proxyAddr,
			headers:  map[string]string{forwardedFor: realClientIP},
			wantAddr: realClientIP,
		},
		{
			// The client prepends its own value; the proxy appends the address
			// it actually saw. Only the rightmost untrusted entry is real.
			name:     "client-prepended entry is skipped",
			enabled:  true,
			proxies:  []string{proxyCIDR},
			remote:   proxyAddr,
			headers:  map[string]string{forwardedFor: spoofedIP + ", " + realClientIP},
			wantAddr: realClientIP,
		},
		{
			name:     "our own proxies are skipped from the right",
			enabled:  true,
			proxies:  []string{proxyCIDR},
			remote:   proxyAddr,
			headers:  map[string]string{forwardedFor: realClientIP + ", 10.9.9.9"},
			wantAddr: realClientIP,
		},
		{
			name:     "port and brackets are stripped",
			enabled:  true,
			proxies:  []string{proxyCIDR},
			remote:   proxyAddr,
			headers:  map[string]string{forwardedFor: realClientIP + ":4242"},
			wantAddr: realClientIP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withTrustedProxies(t, test.enabled, test.proxies...)
			if got := RealIP(forwardedRequest(test.remote, test.headers)); got != test.wantAddr {
				t.Errorf("RealIP() = %q, want %q", got, test.wantAddr)
			}
		})
	}
}

// A client claiming its plaintext request was TLS must not turn off the HTTPS
// redirect or the Secure flag on session cookies.
func TestSchemeIgnoresUntrustedForwardedProto(t *testing.T) {
	withTrustedProxies(t, true, proxyCIDR)

	untrusted := forwardedRequest(clientAddr, map[string]string{forwardedProto: schemeHTTPS})
	if got := scheme(untrusted); got != schemeHTTP {
		t.Errorf("scheme() = %q for an untrusted client claiming https, want %q", got, schemeHTTP)
	}

	trusted := forwardedRequest(proxyAddr, map[string]string{forwardedProto: schemeHTTPS})
	if got := scheme(trusted); got != schemeHTTPS {
		t.Errorf("scheme() = %q behind a trusted proxy, want %q", got, schemeHTTPS)
	}

	// The reverse matters too: a claim of plaintext must not strip Secure from
	// a cookie issued over a real TLS connection.
	downgrade := forwardedRequest(clientAddr, map[string]string{forwardedProto: schemeHTTP})
	downgrade.TLS = &tlsConnectionState
	if got := scheme(downgrade); got != schemeHTTPS {
		t.Errorf("scheme() = %q for a TLS request claiming http, want %q", got, schemeHTTPS)
	}
}

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

// Responses that identify their reader, or ask not to be stored, stay out of a
// shared cache.
func TestCacheDoesNotStorePerCallerResponses(t *testing.T) {
	tests := map[string][2]string{
		"sets a cookie":        {"Set-Cookie", "session=abc"},
		"marked private":       {"Cache-Control", "private, max-age=60"},
		"marked no-store":      {"Cache-Control", "no-store"},
		"varies on a header":   {"Vary", headerAuthorize},
		"varies on everything": {"Vary", "*"},
		"auth challenge":       {"WWW-Authenticate", `Bearer realm="x"`},
	}
	for name, pair := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			header.Set(pair[0], pair[1])
			if _, storable := notStorable(header); storable {
				t.Errorf("notStorable(%v) said the response may be cached", header)
			}
		})
	}

	// Accept-Encoding is part of the cache key, so varying on it is fine.
	encodingVary := http.Header{}
	encodingVary.Set("Vary", "Accept-Encoding")
	if _, storable := notStorable(encodingVary); !storable {
		t.Error("a response varying only on Accept-Encoding was refused, but the key covers it")
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

// A rejected XML body must stop at the gateway rather than being forwarded with
// a body that has already been read.
func TestXXEProtectionBlocksInvalidXML(t *testing.T) {
	reached := false
	handler := BlockExploitsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	}))

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("<unclosed>"))
	request.Header.Set("Content-Type", "application/xml")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if reached {
		t.Error("a rejected XML request was still forwarded to the upstream")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

// Valid XML passes through with a body the upstream can still read.
func TestXXEProtectionPreservesValidBody(t *testing.T) {
	var received string
	handler := BlockExploitsMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
	}))

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("<note>hello</note>"))
	request.Header.Set("Content-Type", "application/xml")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if received != "<note>hello</note>" {
		t.Errorf("upstream received %q, want the original body", received)
	}
}

// The body limit must reject on the declared length, before reading anything.
func TestBodyLimitRejectsOversizedRequests(t *testing.T) {
	reached := false
	limit := BodyLimit{MaxBytes: 16}
	handler := limit.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	}))

	oversized := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 128)))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, oversized)

	if reached {
		t.Error("an oversized body reached the upstream")
	}
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}

	// A body within the limit is passed through intact.
	var received string
	handler = limit.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small")))
	if received != "small" {
		t.Errorf("upstream received %q, want %q", received, "small")
	}
}

// An unknown username must cost what a known one costs, or the user list can be
// enumerated by timing alone.
func TestBasicAuthDoesNotRevealKnownUsernames(t *testing.T) {
	auth := &AuthBasic{Users: []User{{
		Username: "known",
		// bcrypt hash of "secret"
		Password: "$2a$10$f0RTQ0HKSdhvU4h4/nuBse9ROnKBmfSmuPYzV.QcoDHePFqAeUDT2",
	}}}

	if auth.validateCredentials("known", "wrong-password") {
		t.Error("a wrong password was accepted")
	}
	if auth.validateCredentials("unknown", "wrong-password") {
		t.Error("an unknown user was accepted")
	}
	if !auth.validateCredentials("known", "secret") {
		t.Error("the correct credentials were rejected")
	}
}
