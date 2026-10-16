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
)

func withCountry(t *testing.T, on bool, resolve func(string) string) {
	t.Helper()
	prevOn, prevResolve := countryHeaderOn, resolveCountry
	countryHeaderOn, resolveCountry = on, resolve
	t.Cleanup(func() { countryHeaderOn, resolveCountry = prevOn, prevResolve })
}

// upstreamCountry proxies req through the middleware and returns the header the upstream saw.
func upstreamCountry(t *testing.T, req *http.Request) (string, bool) {
	t.Helper()
	var got []string
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Values(CountryHeader)
		w.WriteHeader(http.StatusOK)
	})
	(&ProxyMiddleware{Name: "test"}).Wrap(upstream).ServeHTTP(httptest.NewRecorder(), req)
	if len(got) > 1 {
		t.Fatalf("upstream saw %d country headers, want at most 1: %v", len(got), got)
	}
	if len(got) == 0 {
		return "", false
	}
	return got[0], true
}

func TestCountryHeader(t *testing.T) {
	resolveDE := func(string) string { return "DE" }
	unknown := func(string) string { return "" }

	t.Run("set from the resolved country", func(t *testing.T) {
		withCountry(t, true, resolveDE)
		got, ok := upstreamCountry(t, httptest.NewRequest(http.MethodGet, "/", nil))
		if !ok || got != "DE" {
			t.Fatalf("got %q (present=%v), want DE", got, ok)
		}
	})

	t.Run("client-sent value is replaced", func(t *testing.T) {
		withCountry(t, true, resolveDE)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Add("X-Goma-Country", "US")
		req.Header.Add("x-goma-country", "FR")
		if got, _ := upstreamCountry(t, req); got != "DE" {
			t.Fatalf("got %q, want DE", got)
		}
	})

	t.Run("unknown country strips a forged header", func(t *testing.T) {
		withCountry(t, true, unknown)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Goma-Country", "US")
		if got, ok := upstreamCountry(t, req); ok {
			t.Fatalf("forged header reached the upstream: %q", got)
		}
	})

	t.Run("websocket upgrades are covered too", func(t *testing.T) {
		withCountry(t, true, resolveDE)
		req := httptest.NewRequest(http.MethodGet, "/ws", nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("X-Goma-Country", "US")
		if got, _ := upstreamCountry(t, req); got != "DE" {
			t.Fatalf("got %q, want DE", got)
		}
	})

	t.Run("off leaves request headers alone", func(t *testing.T) {
		withCountry(t, false, resolveDE)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Goma-Country", "US")
		if got, _ := upstreamCountry(t, req); got != "US" {
			t.Fatalf("got %q, want the untouched US", got)
		}
	})
}

func TestCountryHeaderEnabled(t *testing.T) {
	if (GeoIPConfig{}).countryHeaderEnabled() {
		t.Fatal("unset: want off")
	}
	if !(GeoIPConfig{CountryHeader: true}).countryHeaderEnabled() {
		t.Fatal("config true: want on")
	}
	t.Setenv("GOMA_GEOIP_COUNTRY_HEADER", "false")
	if (GeoIPConfig{CountryHeader: true}).countryHeaderEnabled() {
		t.Fatal("env false must override the config")
	}
}
