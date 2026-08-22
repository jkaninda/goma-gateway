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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jkaninda/goma-gateway/internal/config"
)

// Fixtures for the forwarded-header tests.
const (
	clientAddr     = "203.0.113.9:5555"
	clientIP       = "203.0.113.9"
	proxyAddr      = "10.1.2.3:5555"
	proxyCIDR      = "10.0.0.0/8"
	spoofedIP      = "1.2.3.4"
	realClientIP   = "198.51.100.7"
	forwardedProto = "X-Forwarded-Proto"
	forwardedFor   = "X-Forwarded-For"
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
