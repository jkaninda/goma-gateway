/*
 * Copyright 2024 Jonas Kaninda
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package certmanager

import "testing"

func TestNormalize_LegacyConfigMigratesToProviders(t *testing.T) {
	cfg := &Config{
		Provider: CertAcmeProvider,
		Acme:     Acme{Email: "ops@example.com", ChallengeType: HTTP01},
	}
	cfg.Normalize()

	if cfg.DefaultProvider != LegacyProviderName {
		t.Errorf("expected DefaultProvider=%q, got %q", LegacyProviderName, cfg.DefaultProvider)
	}
	p, ok := cfg.Providers[LegacyProviderName]
	if !ok {
		t.Fatalf("expected legacy provider to be migrated into Providers map")
	}
	if p.Acme.Email != "ops@example.com" {
		t.Errorf("legacy Acme block lost: %+v", p.Acme)
	}
	if p.Type != CertAcmeProvider {
		t.Errorf("expected Type=%q, got %q", CertAcmeProvider, p.Type)
	}
}

func TestNormalize_LegacyImpliesAcmeWhenProviderEmpty(t *testing.T) {
	cfg := &Config{Acme: Acme{Email: "ops@example.com"}}
	cfg.Normalize()

	p, ok := cfg.Providers[LegacyProviderName]
	if !ok {
		t.Fatalf("expected legacy migration when only Acme.Email is set")
	}
	if p.Type != CertAcmeProvider {
		t.Errorf("expected Type to default to %q, got %q", CertAcmeProvider, p.Type)
	}
}

func TestNormalize_MultiProviderUnchanged(t *testing.T) {
	cfg := &Config{
		DefaultProvider: "letsencrypt",
		Providers: map[string]ProviderConfig{
			"letsencrypt":         {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com"}},
			"letsencrypt-staging": {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com"}},
		},
	}
	cfg.Normalize()

	if cfg.DefaultProvider != "letsencrypt" {
		t.Errorf("DefaultProvider mutated: %q", cfg.DefaultProvider)
	}
	if len(cfg.Providers) != 2 {
		t.Errorf("Providers count mutated: %d", len(cfg.Providers))
	}
}

func TestNormalize_SingleProviderInfersDefault(t *testing.T) {
	cfg := &Config{
		Providers: map[string]ProviderConfig{
			"only": {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com"}},
		},
	}
	cfg.Normalize()

	if cfg.DefaultProvider != "only" {
		t.Errorf("expected DefaultProvider to be inferred to %q, got %q", "only", cfg.DefaultProvider)
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	cfg := &Config{
		Provider: CertAcmeProvider,
		Acme:     Acme{Email: "ops@example.com"},
	}
	cfg.Normalize()
	first := cfg.DefaultProvider
	firstCount := len(cfg.Providers)
	cfg.Normalize()
	if cfg.DefaultProvider != first || len(cfg.Providers) != firstCount {
		t.Errorf("Normalize is not idempotent: default=%q→%q, providers=%d→%d",
			first, cfg.DefaultProvider, firstCount, len(cfg.Providers))
	}
}

func TestNormalize_NilSafe(t *testing.T) {
	var cfg *Config
	cfg.Normalize() // must not panic
}

func TestResolveProvider(t *testing.T) {
	cfg := &Config{
		DefaultProvider: "letsencrypt",
		Providers: map[string]ProviderConfig{
			"letsencrypt":    {Type: CertAcmeProvider},
			"cloudflare-dns": {Type: CertAcmeProvider},
		},
	}

	tests := []struct {
		routeProvider string
		want          string
	}{
		{"", "letsencrypt"},
		{"cloudflare-dns", "cloudflare-dns"},
		{"none", ""},
		{"NONE", ""},
		{"unknown-provider", "unknown-provider"}, // ResolveProvider does not validate; that happens in goma.
	}
	for _, tc := range tests {
		got := cfg.ResolveProvider(tc.routeProvider)
		if got != tc.want {
			t.Errorf("ResolveProvider(%q) = %q, want %q", tc.routeProvider, got, tc.want)
		}
	}
}

func TestNewCertManager_LegacyConfig(t *testing.T) {
	cfg := &Config{
		Provider: CertAcmeProvider,
		Acme: Acme{
			Email:       "ops@example.com",
			StorageFile: t.TempDir() + "/acme.json",
		},
	}
	cm, err := NewCertManager(cfg)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if !cm.HasProvider(LegacyProviderName) {
		t.Errorf("expected legacy provider %q to exist", LegacyProviderName)
	}
	if cm.DefaultProvider() != LegacyProviderName {
		t.Errorf("expected default provider %q, got %q", LegacyProviderName, cm.DefaultProvider())
	}
}

func TestNewCertManager_MultiProviderHasDistinctStorageFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		DefaultProvider: "prod",
		Providers: map[string]ProviderConfig{
			"prod":    {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com", StorageFile: dir + "/prod.json"}},
			"staging": {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com", StorageFile: dir + "/staging.json"}},
		},
	}
	cm, err := NewCertManager(cfg)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	if cm.providers["prod"].storageFile == cm.providers["staging"].storageFile {
		t.Errorf("providers must not share storage file: %q", cm.providers["prod"].storageFile)
	}
}

func TestNewCertManager_DerivesPerProviderStorageDefault(t *testing.T) {
	cfg := &Config{
		DefaultProvider: "prod",
		Providers: map[string]ProviderConfig{
			"prod":    {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com"}},
			"staging": {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com"}},
		},
	}
	cm, err := NewCertManager(cfg)
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	prod := cm.providers["prod"].storageFile
	stg := cm.providers["staging"].storageFile
	if prod == stg {
		t.Fatalf("derived storage files collide: %q == %q", prod, stg)
	}
	// Legacy provider name must keep historical default to preserve back-compat
	// even when other named providers exist alongside it.
	cfg2 := &Config{
		DefaultProvider: LegacyProviderName,
		Providers: map[string]ProviderConfig{
			LegacyProviderName: {Type: CertAcmeProvider, Acme: Acme{Email: "a@x.com"}},
		},
	}
	cm2, err := NewCertManager(cfg2)
	if err != nil {
		t.Fatalf("NewCertManager (legacy): %v", err)
	}
	if got := cm2.providers[LegacyProviderName].storageFile; got == "" || filepathBase(got) != acmeFile {
		t.Errorf("legacy provider should keep default %q filename, got %q", acmeFile, got)
	}
}

// filepathBase is a tiny helper to avoid importing path/filepath here.
func filepathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
