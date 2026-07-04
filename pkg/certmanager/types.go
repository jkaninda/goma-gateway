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

package certmanager

import "strings"

// LegacyProviderName is the synthetic provider name created by Normalize when
// migrating a legacy single-provider Config (top-level Provider/Acme/Vault) into
// the Providers map. Existing storage files keep working under this name.
const LegacyProviderName = "default"

// NoneProvider opts a Route out of automatic certificate management.
const NoneProvider = "none"

// Config describes the certificate manager. It supports two shapes:
//
//  1. Legacy single-provider (Provider/Acme/Vault at the top level).
//  2. Multi-provider via the Providers map plus DefaultProvider.
//
// Normalize() migrates legacy configs into the Providers map at load time so
// downstream code only has to deal with the multi-provider shape.
type Config struct {
	// DefaultProvider names the provider used when a Route's tlsProvider is empty.
	DefaultProvider string `yaml:"defaultProvider,omitempty"`
	// Providers is the map of named providers keyed by user-chosen name.
	Providers map[string]ProviderConfig `yaml:"providers,omitempty"`

	// Provider is the legacy single-provider type. Deprecated: use Providers.
	Provider CertProvider `yaml:"provider,omitempty"`
	// Acme is the legacy ACME config. Deprecated: use Providers.
	Acme Acme `yaml:"acme,omitempty"`
	// Vault is the legacy Vault config. Deprecated: use Providers.
	Vault Vault `yaml:"vault,omitempty"`
}

// ProviderConfig describes a single named cert provider.
type ProviderConfig struct {
	Type  CertProvider `yaml:"type"`
	Acme  Acme         `yaml:"acme,omitempty"`
	Vault Vault        `yaml:"vault,omitempty"`
}

type Acme struct {
	Email         string        `yaml:"email"`
	DirectoryURL  string        `yaml:"directoryUrl,omitempty"`
	StorageFile   string        `yaml:"storageFile,omitempty"`
	TermsAccepted bool          `yaml:"termsAccepted,omitempty" default:"true"`
	ChallengeType ChallengeType `yaml:"challengeType,omitempty"`
	DnsProvider   DnsProvider   `yaml:"dnsProvider,omitempty"`
	Credentials   Credentials   `yaml:"credentials,omitempty"`
}

type Challenge struct {
	Type     ChallengeType `yaml:"type,omitempty"`
	Provider AcmeProvider  `yaml:"provider,omitempty"`
}
type Credentials struct {
	ApiToken string `yaml:"apiToken,omitempty" env:"GOMA_CREDENTIALS_API_TOKEN, overwrite"`
}
type ChallengeType string
type DnsProvider string
type AcmeProvider string
type CertProvider string

// Vault configures a HashiCorp Vault PKI issuer. Certificates are issued through
// the Vault PKI secrets engine (POST <address>/v1/<mount>/issue/<role>).
type Vault struct {
	// Address is the Vault server base URL (e.g. https://vault.example.com).
	// Falls back to the VAULT_ADDR environment variable when empty.
	Address string `yaml:"address,omitempty"`
	// Token is the Vault token used to authenticate. Prefer the VAULT_TOKEN
	// environment variable over inlining it in the config file.
	Token string `yaml:"token,omitempty"`
	// Role is the PKI role used to issue certificates.
	Role string `yaml:"role,omitempty"`
	// Mount is the PKI secrets engine mount path (default: "pki").
	Mount string `yaml:"mount,omitempty"`
	// Namespace is the Vault Enterprise namespace (optional). Falls back to the
	// VAULT_NAMESPACE environment variable when empty.
	Namespace string `yaml:"namespace,omitempty"`
	// Ttl requests a specific certificate lifetime (e.g. "72h"). Empty uses the
	// PKI role's default TTL.
	Ttl string `yaml:"ttl,omitempty"`
	// StorageFile persists issued certificates (default: <cacheDir>/vault-<name>.json).
	StorageFile string `yaml:"storageFile,omitempty"`
}
type StorageConfig struct {
	CacheDir    string
	StorageFile string
}

// Normalize migrates a legacy single-provider Config into the Providers map and
// fills DefaultProvider when unambiguous. Idempotent.
func (c *Config) Normalize() {
	if c == nil {
		return
	}
	if len(c.Providers) == 0 && c.hasLegacyConfig() {
		provider := c.Provider
		if provider == "" {
			provider = CertAcmeProvider
		}
		c.Providers = map[string]ProviderConfig{
			LegacyProviderName: {Type: provider, Acme: c.Acme, Vault: c.Vault},
		}
		if c.DefaultProvider == "" {
			c.DefaultProvider = LegacyProviderName
		}
	}
	if c.DefaultProvider == "" && len(c.Providers) == 1 {
		for name := range c.Providers {
			c.DefaultProvider = name
		}
	}
}

func (c *Config) hasLegacyConfig() bool {
	return c.Provider != "" ||
		c.Acme.Email != "" ||
		c.Acme.ChallengeType != "" ||
		c.Acme.DirectoryURL != "" ||
		c.Vault.Address != ""
}

// HasProvider reports whether name exists in the Providers map.
func (c *Config) HasProvider(name string) bool {
	if c == nil {
		return false
	}
	_, ok := c.Providers[name]
	return ok
}

// ResolveProvider maps a Route's tlsProvider value to the provider name that
// should issue certificates for that route. Returns:
//   - "" if the route opted out ("none") or no provider is configured.
//   - The named provider when set on the route.
//   - DefaultProvider when the route leaves tlsProvider empty.
func (c *Config) ResolveProvider(routeProvider string) string {
	if c == nil {
		return ""
	}
	if strings.EqualFold(routeProvider, NoneProvider) {
		return ""
	}
	if routeProvider != "" {
		return routeProvider
	}
	return c.DefaultProvider
}
