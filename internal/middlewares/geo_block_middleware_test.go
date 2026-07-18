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
	"net/http"
	"net/http/httptest"
	"testing"
)

func countrySet(cc ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(cc))
	for _, c := range cc {
		m[c] = struct{}{}
	}
	return m
}

// serve runs a request with the given remote IP through g and returns the status
// plus the country header the upstream saw (if any).
func serve(g GeoBlock, remoteIP string) (int, string) {
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g.CountryHeader != "" {
			seen = r.Header.Get(g.CountryHeader)
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteIP + ":12345"
	rec := httptest.NewRecorder()
	g.Middleware(next).ServeHTTP(rec, req)
	return rec.Code, seen
}

func TestGeoBlockAllowlist(t *testing.T) {
	// ALLOW: only FR/DE pass.
	g := GeoBlock{
		Countries: countrySet("FR", "DE"),
		Resolve:   func(ip string) string { return map[string]string{"1.1.1.1": "FR", "2.2.2.2": "US"}[ip] },
	}
	if code, _ := serve(g, "1.1.1.1"); code != http.StatusOK {
		t.Errorf("FR should pass allowlist, got %d", code)
	}
	if code, _ := serve(g, "2.2.2.2"); code != http.StatusForbidden {
		t.Errorf("US should be blocked by allowlist, got %d", code)
	}
}

func TestGeoBlockBlocklist(t *testing.T) {
	// DENY: CN/RU blocked, everything else passes.
	g := GeoBlock{
		Deny:      true,
		Countries: countrySet("CN", "RU"),
		Resolve:   func(ip string) string { return map[string]string{"1.1.1.1": "CN", "2.2.2.2": "US"}[ip] },
	}
	if code, _ := serve(g, "1.1.1.1"); code != http.StatusForbidden {
		t.Errorf("CN should be blocked by blocklist, got %d", code)
	}
	if code, _ := serve(g, "2.2.2.2"); code != http.StatusOK {
		t.Errorf("US should pass blocklist, got %d", code)
	}
}

func TestGeoBlockUnknownFailOpenAndClosed(t *testing.T) {
	base := func(allowUnknown bool) GeoBlock {
		return GeoBlock{
			Countries:    countrySet("FR"),
			AllowUnknown: allowUnknown,
			Resolve:      func(ip string) string { return "" }, // unresolved
		}
	}
	if code, _ := serve(base(true), "8.8.8.8"); code != http.StatusOK {
		t.Errorf("fail-open: unknown should pass, got %d", code)
	}
	if code, _ := serve(base(false), "8.8.8.8"); code != http.StatusForbidden {
		t.Errorf("fail-closed: unknown should be blocked, got %d", code)
	}
}

func TestGeoBlockPrivateIPBypasses(t *testing.T) {
	// A private client is never geo-fenced, even under a strict allowlist.
	g := GeoBlock{
		Countries:    countrySet("FR"),
		AllowUnknown: false,
		Resolve:      func(ip string) string { return "US" }, // would otherwise be blocked
	}
	if code, _ := serve(g, "10.1.2.3"); code != http.StatusOK {
		t.Errorf("private IP should bypass geo check, got %d", code)
	}
}

func TestGeoBlockCountryHeaderInjected(t *testing.T) {
	g := GeoBlock{
		Countries:     countrySet("US"),
		CountryHeader: "X-Country-Code",
		Resolve:       func(ip string) string { return "us" }, // lower-case, normalized to US
	}
	code, seen := serve(g, "3.3.3.3")
	if code != http.StatusOK {
		t.Fatalf("US should pass, got %d", code)
	}
	if seen != "US" {
		t.Errorf("upstream country header = %q, want US", seen)
	}
}

func TestGeoBlockCustomStatusAndDeny(t *testing.T) {
	var denied string
	g := GeoBlock{
		Countries:  countrySet("FR"),
		StatusCode: http.StatusTeapot,
		Resolve:    func(ip string) string { return "US" },
		OnDeny:     func(country string) { denied = country },
	}
	code, _ := serve(g, "4.4.4.4")
	if code != http.StatusTeapot {
		t.Errorf("custom status = %d, want 418", code)
	}
	if denied != "US" {
		t.Errorf("OnDeny country = %q, want US", denied)
	}
}
