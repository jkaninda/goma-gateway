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

package config

import (
	"net"
	"strings"
)

type ProxyConfig struct {
	Enabled         bool     `yaml:"enabled,omitempty"`
	TrustedProxies  []string `yaml:"trustedProxies,omitempty"` // CIDR or single IPs
	IPHeaders       []string `yaml:"ipHeaders,omitempty"`      // header order of trust
	trustedNetworks []*net.IPNet
}

// Init prepares trustedNetworks (parse CIDRs) for runtime use.
func (p *ProxyConfig) Init() (*ProxyConfig, error) {
	if !p.Enabled || len(p.trustedNetworks) > 0 {
		return p, nil
	}
	p.trustedNetworks = make([]*net.IPNet, 0, len(p.TrustedProxies))
	for _, entry := range p.TrustedProxies {
		if !strings.Contains(entry, "/") {
			if ip := net.ParseIP(entry); ip != nil {
				entry += "/32"
				if ip.To16() != nil && ip.To4() == nil {
					entry = entry[:len(entry)-3] + "/128" // IPv6
				}
			}
		}
		if _, ipnet, err := net.ParseCIDR(entry); err == nil {
			p.trustedNetworks = append(p.trustedNetworks, ipnet)
		} else {
			return p, err
		}
	}
	if len(p.IPHeaders) == 0 {
		p.IPHeaders = []string{"X-Forwarded-For", "X-Real-IP"}
	}
	return p, nil
}

// IsTrustedSource checks whether the given IP belongs to a trusted proxy.
func (p *ProxyConfig) IsTrustedSource(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range p.trustedNetworks {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}
