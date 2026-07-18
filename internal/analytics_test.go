/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"encoding/json"
	"strings"
	"testing"
)

// refererHost must reduce a referer to its host — a path/query can carry tokens,
// so only the host may be emitted.
func TestRefererHostStripsPathAndQuery(t *testing.T) {
	cases := map[string]string{
		"https://news.ycombinator.com/item?id=123&token=secret": "news.ycombinator.com",
		"http://example.com/a/b/c":                              "example.com",
		"":                                                      "",
	}
	for in, want := range cases {
		if got := refererHost(in); got != want {
			t.Errorf("refererHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// visitorID must be deterministic within a day, distinct for different inputs,
// and must never contain the raw IP (privacy).
func TestVisitorIDStableDistinctAndNoIP(t *testing.T) {
	const ip, ua = "203.0.113.7", "Mozilla/5.0 (Macintosh)"
	a := visitorID(ip, ua)
	if a != visitorID(ip, ua) {
		t.Fatal("visitorID not stable for the same (ip, ua) within a day")
	}
	if a == visitorID("203.0.113.8", ua) {
		t.Error("visitorID collided for different IPs")
	}
	if a == visitorID(ip, "curl/8.0") {
		t.Error("visitorID collided for different user agents")
	}
	if strings.Contains(a, ip) {
		t.Errorf("visitorID leaks the raw IP: %q", a)
	}
	if len(a) != 16 { // hex of the first 8 bytes of a sha256
		t.Errorf("visitorID length = %d, want 16", len(a))
	}
}

// The emitted JSON is the contract Miabi consumes: identity + path_template +
// vid present; no raw IP field anywhere.
func TestAnalyticsEventJSONContract(t *testing.T) {
	e := &AnalyticsEvent{
		Ts: 1, Route: "ws12-web", Host: "app.acme.com", Method: "GET", Status: 200,
		Path: "/blog/hello", PathTemplate: "/blog/:slug", RespBytes: 14210,
		DurationMs: 34, UpstreamMs: 28, VID: "abc123", UA: "Mozilla/5.0",
		RefererHost: "news.ycombinator.com",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, must := range []string{`"name":"ws12-web"`, `"path_template":"/blog/:slug"`, `"vid":"abc123"`, `"upstream_ms":28`} {
		if !strings.Contains(s, must) {
			t.Errorf("event JSON missing %s:\n%s", must, s)
		}
	}
	if strings.Contains(strings.ToLower(s), `"ip"`) {
		t.Errorf("event JSON must not carry an IP field:\n%s", s)
	}
}
