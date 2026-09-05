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

package certmanager

import (
	"crypto/tls"
	"testing"
	"time"
)

// certFor returns a CertificateInfo whose leaf is irrelevant to matching: only
// Domains and Expires are consulted by the lookup path.
func certFor(domains ...string) *CertificateInfo {
	return &CertificateInfo{
		Certificate: &tls.Certificate{},
		Domains:     domains,
		Expires:     time.Now().Add(72 * time.Hour),
	}
}

func TestMatchesWildcardDomain(t *testing.T) {
	tests := []struct {
		requested, pattern string
		want               bool
	}{
		{"certio.jkaninda.dev", "*.jkaninda.dev", true},
		{"miabi-it40tdf0.apps.jkaninda.dev", "*.jkaninda.dev", false},
		{"miabi-it40tdf0.apps.jkaninda.dev", "*.apps.jkaninda.dev", true},
		{"jkaninda.dev", "*.jkaninda.dev", false},
		{"CERTIO.jkaninda.dev", "*.jkaninda.dev", true},
		{"certio.jkaninda.dev", "certio.jkaninda.dev", false},
		{"certio.jkaninda.dev", "*.other.dev", false},
		{".jkaninda.dev", "*.jkaninda.dev", false},
	}
	for _, tt := range tests {
		if got := matchesWildcardDomain(tt.requested, tt.pattern); got != tt.want {
			t.Errorf("matchesWildcardDomain(%q, %q) = %v, want %v", tt.requested, tt.pattern, got, tt.want)
		}
	}
}

func TestFindBestCertificateInPrefersExactOverWildcard(t *testing.T) {
	certs := map[string]*CertificateInfo{
		"*.jkaninda.dev":      certFor("*.jkaninda.dev"),
		"certio.jkaninda.dev": certFor("certio.jkaninda.dev"),
	}

	for i := 0; i < 50; i++ {
		got, rank := findBestCertificateIn(certs, "certio.jkaninda.dev", false)
		if rank != matchExact || got != certs["certio.jkaninda.dev"] {
			t.Fatalf("got rank %v cert %v, want the exact certio certificate", rank, got.Domains)
		}
	}
}

func TestFindBestCertificateInFallsBackToWildcard(t *testing.T) {
	certs := map[string]*CertificateInfo{"*.jkaninda.dev": certFor("*.jkaninda.dev")}

	got, rank := findBestCertificateIn(certs, "other.jkaninda.dev", false)
	if rank != matchWildcard || got == nil {
		t.Fatalf("got rank %v, want the wildcard certificate", rank)
	}

	// A wildcard spans a single label, so it must not claim a deeper host.
	if got, rank = findBestCertificateIn(certs, "miabi-it40tdf0.apps.jkaninda.dev", false); rank != matchNone {
		t.Fatalf("wildcard wrongly claimed a two-label subdomain: rank %v, cert %v", rank, got)
	}
}

func TestFindBestCertificateInSkipsExpired(t *testing.T) {
	expired := certFor("certio.jkaninda.dev")
	expired.Expires = time.Now().Add(-time.Hour)
	certs := map[string]*CertificateInfo{
		"certio.jkaninda.dev": expired,
		"*.jkaninda.dev":      certFor("*.jkaninda.dev"),
	}

	got, rank := findBestCertificateIn(certs, "certio.jkaninda.dev", false)
	if rank != matchWildcard || got != certs["*.jkaninda.dev"] {
		t.Fatalf("got rank %v, want the wildcard to cover the expired exact cert", rank)
	}
}

func TestGetCertificatePrefersExactAcrossPools(t *testing.T) {
	exact := certFor("certio.jkaninda.dev")
	cm := &CertManager{
		customCerts: map[string]*CertificateInfo{"*.jkaninda.dev": certFor("*.jkaninda.dev")},
		providers: map[string]*provider{"acme": {
			name:  "acme",
			certs: map[string]*CertificateInfo{"certio.jkaninda.dev": exact},
		}},
	}

	got, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "certio.jkaninda.dev"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != exact.Certificate {
		t.Error("wildcard custom cert shadowed the provider's exact certificate")
	}
}

func TestIsHostAllowedPrefersExactRoute(t *testing.T) {
	wildcardRoute := Domain{Name: "wildcard", Hosts: []string{"*.jkaninda.dev"}}
	exactRoute := Domain{Name: "certio", Hosts: []string{"certio.jkaninda.dev"}}
	p := &provider{allowedHosts: []Domain{wildcardRoute, exactRoute}}

	ok, route := p.isHostAllowed("certio.jkaninda.dev")
	if !ok || route.Name != "certio" {
		t.Errorf("got (%v, %q), want the exact route", ok, route.Name)
	}

	ok, route = p.isHostAllowed("other.jkaninda.dev")
	if !ok || route.Name != "wildcard" {
		t.Errorf("got (%v, %q), want the wildcard route", ok, route.Name)
	}

	if ok, _ = p.isHostAllowed("miabi-it40tdf0.apps.jkaninda.dev"); ok {
		t.Error("wildcard route wrongly claimed a two-label subdomain")
	}
}

func TestGetCertificateServesWildcardAndOrdersExact(t *testing.T) {
	wildcard := certFor("*.jkaninda.dev")
	p := &provider{
		name:         "acme",
		certs:        map[string]*CertificateInfo{"*.jkaninda.dev": wildcard},
		allowedHosts: []Domain{{Name: "certio", Hosts: []string{"certio.jkaninda.dev"}}},
	}
	cm := &CertManager{
		customCerts: map[string]*CertificateInfo{},
		providers:   map[string]*provider{"acme": p},
	}

	got, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "certio.jkaninda.dev"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != wildcard.Certificate {
		t.Error("handshake was not served the covering wildcard certificate")
	}
	if _, ok := cm.onDemandAttempts["certio.jkaninda.dev"]; !ok {
		t.Error("no background certificate order was started for the uncovered host")
	}
}

func TestGetCertificateDoesNotOrderWhenExactCertExists(t *testing.T) {
	p := &provider{
		name:         "acme",
		certs:        map[string]*CertificateInfo{"certio.jkaninda.dev": certFor("certio.jkaninda.dev")},
		allowedHosts: []Domain{{Name: "certio", Hosts: []string{"certio.jkaninda.dev"}}},
	}
	cm := &CertManager{customCerts: map[string]*CertificateInfo{}, providers: map[string]*provider{"acme": p}}

	if _, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "certio.jkaninda.dev"}); err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if len(cm.onDemandAttempts) != 0 {
		t.Errorf("ordered a certificate for a host that already has one: %v", cm.onDemandAttempts)
	}
}

func TestGetCertificateDoesNotOrderForUnclaimedSNI(t *testing.T) {
	cm := &CertManager{
		customCerts: map[string]*CertificateInfo{},
		providers:   map[string]*provider{"acme": {name: "acme"}},
		defaultCert: &tls.Certificate{},
	}

	got, err := cm.GetCertificate(&tls.ClientHelloInfo{ServerName: "stranger.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != cm.defaultCert {
		t.Error("expected the default certificate for an unclaimed SNI")
	}
	if len(cm.onDemandAttempts) != 0 {
		t.Error("started an ACME order for a host no provider claims")
	}
}

func TestOnDemandAttemptThrottles(t *testing.T) {
	cm := &CertManager{customCerts: map[string]*CertificateInfo{}, providers: map[string]*provider{}}

	if !cm.beginOnDemandAttempt("certio.jkaninda.dev") {
		t.Fatal("first attempt was refused")
	}
	if cm.beginOnDemandAttempt("certio.jkaninda.dev") {
		t.Fatal("a second attempt started while the first was still reserved")
	}

	// No certificate turned up, so the window widens instead of clearing.
	cm.finishOnDemandAttempt("certio.jkaninda.dev")
	attempt := cm.onDemandAttempts["certio.jkaninda.dev"]
	if attempt == nil || attempt.failures != 1 {
		t.Fatalf("expected one recorded failure, got %+v", attempt)
	}
	if cm.beginOnDemandAttempt("certio.jkaninda.dev") {
		t.Error("retried before the backoff window elapsed")
	}

	// Once the certificate exists the host stops being retried.
	cm.customCerts["certio.jkaninda.dev"] = certFor("certio.jkaninda.dev")
	cm.finishOnDemandAttempt("certio.jkaninda.dev")
	if len(cm.onDemandAttempts) != 0 {
		t.Error("throttle state survived a successful issuance")
	}
}

func TestOnDemandBackoffGrowsAndCaps(t *testing.T) {
	if got := onDemandBackoff(0); got != onDemandBaseBackoff {
		t.Errorf("onDemandBackoff(0) = %v, want %v", got, onDemandBaseBackoff)
	}
	if got := onDemandBackoff(2); got != 4*onDemandBaseBackoff {
		t.Errorf("onDemandBackoff(2) = %v, want %v", got, 4*onDemandBaseBackoff)
	}
	if got := onDemandBackoff(64); got != onDemandMaxBackoff {
		t.Errorf("onDemandBackoff(64) = %v, want the %v cap", got, onDemandMaxBackoff)
	}
}

func TestShouldSkipDomainRequiresExactCertificate(t *testing.T) {
	p := &provider{
		name:               "acme",
		certs:              map[string]*CertificateInfo{"*.jkaninda.dev": certFor("*.jkaninda.dev")},
		inProgressRequests: map[string]bool{},
	}

	covered := Domain{Name: "certio", Hosts: []string{"certio.jkaninda.dev"}}
	if p.shouldSkipDomain(covered, false) {
		t.Error("a wildcard-covered route was skipped instead of getting its own certificate")
	}

	wildcardRoute := Domain{Name: "wildcard", Hosts: []string{"*.jkaninda.dev"}}
	if !p.shouldSkipDomain(wildcardRoute, false) {
		t.Error("the wildcard route was re-requested despite holding its own certificate")
	}
}
