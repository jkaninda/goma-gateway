/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// The analytics block must round-trip from the config file, so an operator can
// configure it without setting a single environment variable.
func TestAnalyticsConfigFromYAML(t *testing.T) {
	const doc = `
analytics:
  enabled: true
  stream: custom:events
  sample: 0.25
  maxLen: 5000
  gatewayId: edge-1
geoip:
  database: /etc/goma/country.mmdb
routes: []
`
	var g Gateway
	if err := yaml.Unmarshal([]byte(doc), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	a := g.Analytics
	if !a.analyticsEnabled() {
		t.Error("enabled: got false, want true")
	}
	if got := a.streamName(); got != "custom:events" {
		t.Errorf("stream = %q, want custom:events", got)
	}
	if got := a.sampleRate(); got != 0.25 {
		t.Errorf("sample = %v, want 0.25", got)
	}
	if got := a.streamMaxLen(); got != 5000 {
		t.Errorf("maxLen = %d, want 5000", got)
	}
	if got := a.gatewayIdentifier(); got != "edge-1" {
		t.Errorf("gatewayId = %q, want edge-1", got)
	}
	if got := g.GeoIP.databasePath(); got != "/etc/goma/country.mmdb" {
		t.Errorf("geoip.database = %q, want /etc/goma/country.mmdb", got)
	}
}

// GeoIP is top-level, not nested under analytics: the geoBlock middleware and
// the by-country metric read the same database, so a gateway that only does geo
// blocking must be able to configure it without turning analytics on.
func TestGeoIPConfiguredWithoutAnalytics(t *testing.T) {
	const doc = `
geoip:
  database: /srv/geoip/dbip-country-lite.mmdb
routes: []
`
	var g Gateway
	if err := yaml.Unmarshal([]byte(doc), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if g.Analytics.analyticsEnabled() {
		t.Error("analytics enabled by a geoip-only config")
	}
	if got := g.GeoIP.databasePath(); got != "/srv/geoip/dbip-country-lite.mmdb" {
		t.Errorf("geoip.database = %q, want the configured path", got)
	}
}

// An absent analytics block must leave the emitter off and every accessor on its
// documented default — adding the section must not change existing deployments.
func TestAnalyticsConfigDefaults(t *testing.T) {
	var a AnalyticsConfig
	if a.analyticsEnabled() {
		t.Error("analytics enabled by default; it must be opt-in")
	}
	if got := a.streamName(); got != defaultAnalyticsStream {
		t.Errorf("stream = %q, want %q", got, defaultAnalyticsStream)
	}
	if got := a.sampleRate(); got != 1 {
		t.Errorf("sample = %v, want 1 (record everything)", got)
	}
	if got := a.streamMaxLen(); got != defaultAnalyticsMaxLen {
		t.Errorf("maxLen = %d, want %d", got, defaultAnalyticsMaxLen)
	}
	var geo GeoIPConfig
	if got := geo.databasePath(); got != "" {
		t.Errorf("geoip.database = %q, want empty (search the well-known paths)", got)
	}
}

// The environment wins over the file, so an existing GOMA_ANALYTICS_* deployment
// keeps working and a container can override what the config ships with.
func TestAnalyticsEnvOverridesConfig(t *testing.T) {
	cfg := AnalyticsConfig{
		Enabled:   false,
		Stream:    "from:file",
		Sample:    0.1,
		MaxLen:    10,
		GatewayID: "file-gw",
	}
	geo := GeoIPConfig{Database: "/from/file.mmdb"}
	t.Setenv("GOMA_ANALYTICS_ENABLED", "true")
	t.Setenv("GOMA_ANALYTICS_STREAM", "from:env")
	t.Setenv("GOMA_ANALYTICS_SAMPLE", "0.5")
	t.Setenv("GOMA_ANALYTICS_MAXLEN", "999")
	t.Setenv("GOMA_GATEWAY_ID", "env-gw")
	t.Setenv("GOMA_GEOIP_DB", "/from/env.mmdb")

	if !cfg.analyticsEnabled() {
		t.Error("GOMA_ANALYTICS_ENABLED did not override enabled:false")
	}
	if got := cfg.streamName(); got != "from:env" {
		t.Errorf("stream = %q, want from:env", got)
	}
	if got := cfg.sampleRate(); got != 0.5 {
		t.Errorf("sample = %v, want 0.5", got)
	}
	if got := cfg.streamMaxLen(); got != 999 {
		t.Errorf("maxLen = %d, want 999", got)
	}
	if got := cfg.gatewayIdentifier(); got != "env-gw" {
		t.Errorf("gatewayId = %q, want env-gw", got)
	}
	if got := geo.databasePath(); got != "/from/env.mmdb" {
		t.Errorf("geoip.database = %q, want /from/env.mmdb", got)
	}
}

// A malformed numeric override must fall back to the configured value rather
// than to a default — silently dropping to sample=1 or an uncapped stream is
// exactly the failure an operator would not notice.
func TestAnalyticsInvalidEnvFallsBackToConfig(t *testing.T) {
	cfg := AnalyticsConfig{Sample: 0.3, MaxLen: 42}
	t.Setenv("GOMA_ANALYTICS_SAMPLE", "not-a-number")
	t.Setenv("GOMA_ANALYTICS_MAXLEN", "-5")

	if got := cfg.sampleRate(); got != 0.3 {
		t.Errorf("sample = %v, want the configured 0.3", got)
	}
	if got := cfg.streamMaxLen(); got != 42 {
		t.Errorf("maxLen = %d, want the configured 42", got)
	}
}
