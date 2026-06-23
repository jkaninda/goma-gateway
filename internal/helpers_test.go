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
	"testing"

	"github.com/jkaninda/goma-gateway/pkg/certmanager"
)

func TestValidateIPAddress(t *testing.T) {
	tests := []string{
		"192.168.1.100",
		"192.168.1.120",
	}
	for _, test := range tests {
		if validateIPAddress(test) {
			fmt.Println("Ip is valid")
		} else {
			fmt.Println("Ip is invalid")
		}
	}

}
func TestValidateIPOrCIDR(t *testing.T) {
	tests := []string{
		"192.168.1.100",
		"192.168.1.100",
		"192.168.1.100/32",
		"invalid-input",
		"192.168.1.100/33",
	}
	for _, test := range tests {
		isIP, isCIDR := isIPOrCIDR(test)
		if isIP {
			fmt.Printf("%s is an IP address\n", test)
		} else if isCIDR {
			fmt.Printf("%s is a CIDR\n", test)
		} else {
			fmt.Printf("%s is neither an IP address nor a CIDR\n", test)
		}
	}

}

func TestExtractHostsFromRoutes(t *testing.T) {
	routes := []Route{
		{Name: "managed", Hosts: []string{"a.example.com"}, Enabled: true},
		{Name: "opt-out", Hosts: []string{"b.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: "none"}},
		{Name: "opt-out-mixed-case", Hosts: []string{"c.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: "None"}},
		{Name: "disabled", Hosts: []string{"d.example.com"}, Enabled: false},
		{Name: "no-hosts", Enabled: true},
		{Name: "explicit-default", Hosts: []string{"e.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: ""}},
	}

	got := extractHostsFromRoutes(routes)

	wantNames := map[string]bool{"managed": true, "explicit-default": true}
	if len(got) != len(wantNames) {
		t.Fatalf("expected %d domains, got %d: %+v", len(wantNames), len(got), got)
	}
	for _, d := range got {
		if !wantNames[d.Name] {
			t.Errorf("unexpected domain in result: %q (tls.provider opt-out should have excluded it)", d.Name)
		}
	}
}

func TestExtractHostsByProvider(t *testing.T) {
	routes := []Route{
		{Name: "default-1", Hosts: []string{"a.example.com"}, Enabled: true},
		{Name: "default-2", Hosts: []string{"b.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: ""}},
		{Name: "named", Hosts: []string{"c.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: "cloudflare-dns"}},
		{Name: "named-staging", Hosts: []string{"d.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: "letsencrypt-staging"}},
		{Name: "opt-out", Hosts: []string{"e.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: "none"}},
		{Name: "opt-out-cap", Hosts: []string{"f.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: "NONE"}},
		{Name: "disabled", Hosts: []string{"g.example.com"}, Enabled: false, TLS: TlsCertificate{Provider: "cloudflare-dns"}},
		{Name: "no-hosts", Enabled: true, TLS: TlsCertificate{Provider: "cloudflare-dns"}},
	}

	got := extractHostsByProvider(routes, "letsencrypt")

	want := map[string]map[string]bool{
		"letsencrypt":         {"default-1": true, "default-2": true},
		"cloudflare-dns":      {"named": true},
		"letsencrypt-staging": {"named-staging": true},
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d providers, got %d: %v", len(want), len(got), keysOf(got))
	}
	for provider, names := range want {
		gotForProvider, ok := got[provider]
		if !ok {
			t.Errorf("provider %q missing from result", provider)
			continue
		}
		if len(gotForProvider) != len(names) {
			t.Errorf("provider %q: expected %d routes, got %d (%+v)", provider, len(names), len(gotForProvider), gotForProvider)
		}
		for _, d := range gotForProvider {
			if !names[d.Name] {
				t.Errorf("provider %q: unexpected route %q in result", provider, d.Name)
			}
		}
	}
}

func TestExtractHostsByProvider_NoDefault(t *testing.T) {
	routes := []Route{
		{Name: "no-default", Hosts: []string{"a.example.com"}, Enabled: true},
		{Name: "named", Hosts: []string{"b.example.com"}, Enabled: true, TLS: TlsCertificate{Provider: "vault"}},
	}

	got := extractHostsByProvider(routes, "")

	if _, ok := got[""]; ok {
		t.Errorf("routes with empty tls.provider should be dropped when defaultProvider is unset, got: %+v", got[""])
	}
	if len(got["vault"]) != 1 {
		t.Errorf("named route should still be partitioned, got: %+v", got)
	}
}

func keysOf(m map[string][]certmanager.Domain) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
