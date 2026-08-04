/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"strings"
	"testing"
)

func gomaWithDefaults(defaults []string, routes []Route, mws []Middleware) *Goma {
	g := &Goma{gateway: &Gateway{Routes: routes}}
	g.gateway.Defaults.Middlewares = defaults
	g.dynamicRoutes = append([]Route(nil), routes...)
	g.dynamicMiddlewares = mws
	return g
}

func defined(names ...string) []Middleware {
	out := make([]Middleware, 0, len(names))
	for _, n := range names {
		out = append(out, Middleware{Name: n, Type: accessLog})
	}
	return out
}

// Defaults are prepended, and a route that already names one keeps its own
// position — that is how a route re-orders a default relative to its own chain.
func TestDefaultMiddlewaresArePrependedAndDeduped(t *testing.T) {
	g := gomaWithDefaults(
		[]string{"sec", "log"},
		[]Route{
			{Name: "a", Middlewares: []string{"own"}},
			{Name: "b", Middlewares: []string{"log", "own"}}, // already lists a default
			{Name: "c"},
		},
		defined("sec", "log", "own"),
	)
	if err := g.attachDefaultConfigurations(); err != nil {
		t.Fatalf("attach: %v", err)
	}
	want := map[string]string{
		"a": "sec,log,own",
		"b": "sec,log,own", // "log" not duplicated; the route's position wins
		"c": "sec,log",
	}
	for _, r := range g.dynamicRoutes {
		if got := strings.Join(r.Middlewares, ","); got != want[r.Name] {
			t.Errorf("route %s = %q, want %q", r.Name, got, want[r.Name])
		}
	}
}

// A default naming no defined middleware must fail the load. It is applied to
// every route, so accepting it yields a configuration that looks protective and
// enforces nothing — the failure an operator is least likely to notice.
func TestUndefinedDefaultMiddlewareIsRejected(t *testing.T) {
	g := gomaWithDefaults(
		[]string{"sec", "typoed-name"},
		[]Route{{Name: "a"}},
		defined("sec"),
	)
	err := g.attachDefaultConfigurations()
	if err == nil {
		t.Fatal("an undefined default middleware was accepted")
	}
	if !strings.Contains(err.Error(), "typoed-name") {
		t.Errorf("error should name the offending middleware, got: %v", err)
	}
	// Nothing may be applied when the set is invalid.
	if len(g.dynamicRoutes[0].Middlewares) != 0 {
		t.Errorf("defaults were applied despite the error: %v", g.dynamicRoutes[0].Middlewares)
	}
}

// Initialize runs again on every reload. Attaching defaults must not write them
// back into the parsed configuration, or the next reload would start from a route
// list the operator never wrote — and removing a default would stop working.
func TestAttachingDefaultsDoesNotMutateParsedConfig(t *testing.T) {
	routes := []Route{{Name: "a", Middlewares: []string{"own"}}}
	g := gomaWithDefaults([]string{"sec"}, routes, defined("sec", "own"))

	for i := 0; i < 3; i++ { // simulate repeated reloads
		g.dynamicRoutes = append([]Route(nil), g.gateway.Routes...)
		if err := g.attachDefaultConfigurations(); err != nil {
			t.Fatalf("attach %d: %v", i, err)
		}
		if got := strings.Join(g.dynamicRoutes[0].Middlewares, ","); got != "sec,own" {
			t.Fatalf("reload %d produced %q, want sec,own", i, got)
		}
	}
	// The parsed route is untouched, so a later reload still sees what the file says.
	if got := strings.Join(g.gateway.Routes[0].Middlewares, ","); got != "own" {
		t.Errorf("parsed config was mutated: route now carries %q, want own", got)
	}
}

// No defaults configured is a no-op, and must not error on routes referencing
// middlewares this function does not look at.
func TestNoDefaultsIsANoOp(t *testing.T) {
	g := gomaWithDefaults(nil, []Route{{Name: "a", Middlewares: []string{"whatever"}}}, nil)
	if err := g.attachDefaultConfigurations(); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if got := strings.Join(g.dynamicRoutes[0].Middlewares, ","); got != "whatever" {
		t.Errorf("route was modified: %q", got)
	}
}
