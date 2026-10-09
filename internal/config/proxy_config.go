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
	"fmt"
	"net"
	"os"
	"strings"

	goutils "github.com/jkaninda/go-utils"
)

// Environment overrides for the proxy section, so a deployer can set the trusted
// proxies without editing a config file it does not own.
const (
	ProxyEnabledEnv        = "GOMA_PROXY_ENABLED"
	ProxyTrustedProxiesEnv = "GOMA_PROXY_TRUSTED_PROXIES"
	ProxyIPHeadersEnv      = "GOMA_PROXY_IP_HEADERS"
)

type ProxyConfig struct {
	Enabled         bool     `yaml:"enabled,omitempty"`
	TrustedProxies  []string `yaml:"trustedProxies,omitempty"` // CIDR or single IPs
	IPHeaders       []string `yaml:"ipHeaders,omitempty"`      // header order of trust
	trustedNetworks []*net.IPNet
}

// ApplyEnv overlays the GOMA_PROXY_* variables on the file's proxy section. A set,
// non-empty variable wins; the lists are comma-separated.
func (p *ProxyConfig) ApplyEnv() {
	p.Enabled = goutils.EnvBool(ProxyEnabledEnv, p.Enabled)
	if list := envList(ProxyTrustedProxiesEnv); list != nil {
		p.TrustedProxies = list
	}
	if list := envList(ProxyIPHeadersEnv); list != nil {
		p.IPHeaders = list
	}
}

func envList(name string) []string {
	var list []string
	for _, entry := range strings.Split(os.Getenv(name), ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			list = append(list, trimmed)
		}
	}
	return list
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

	if len(p.trustedNetworks) == 0 {
		return p, fmt.Errorf("forwardedHeaders are enabled but trustedProxies is empty, so forwarded " +
			"headers are ignored: list the IPs or CIDRs of the proxies in front of the gateway, or " +
			"disable the feature. Behind a CDN, see " +
			"https://goma.jkaninda.dev/usermanual/running-behind-a-proxy.html")
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
