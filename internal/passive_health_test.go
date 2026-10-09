/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"gopkg.in/yaml.v3"
)

// resetPassiveHealth gives a test a clean, enabled registry with the default
// settings, and leaves one behind.
func resetPassiveHealth(t *testing.T) {
	t.Helper()
	reset := func() {
		passiveBackendHealth.configure(defaultPassiveMaxFails, defaultPassiveEjectFor, false)
		passiveBackendHealth.configure(defaultPassiveMaxFails, defaultPassiveEjectFor, true)
		passiveBackendHealth.now = time.Now
	}
	reset()
	t.Cleanup(reset)
}

// ejections reads the passive-ejection counter for one backend.
func ejections(t *testing.T, endpoint string) float64 {
	t.Helper()
	var m dto.Metric
	if err := prometheusMetrics.GatewayBackendEjections.WithLabelValues(endpoint).Write(&m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// deadEndpoint returns an http:// URL on which nothing is listening, so a dial
// to it is refused.
func deadEndpoint(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return "http://" + addr
}

func TestPassiveHealthEjectsAfterMaxFails(t *testing.T) {
	now := time.Unix(1000, 0)
	p := newPassiveHealth(2, 10*time.Second)
	p.now = func() time.Time { return now }
	const ep = "http://a:8080"

	if ejected, _ := p.recordFailure(ep); ejected || p.isEjected(ep) {
		t.Fatal("one failure must not eject")
	}
	p.recordSuccess(ep)
	if ejected, _ := p.recordFailure(ep); ejected {
		t.Fatal("a success must reset the failure streak")
	}
	ejected, ejectFor := p.recordFailure(ep)
	if !ejected || ejectFor != 10*time.Second || !p.isEjected(ep) {
		t.Fatalf("second consecutive failure must eject: ejected=%v for=%v", ejected, ejectFor)
	}
	if again, _ := p.recordFailure(ep); again {
		t.Fatal("an ejected endpoint must not be re-ejected while it is out")
	}

	// The cooldown expires: the endpoint is back, on probation.
	now = now.Add(10 * time.Second)
	if p.isEjected(ep) {
		t.Fatal("ejection must expire after ejectFor")
	}
	if ejected, _ := p.recordFailure(ep); !ejected {
		t.Fatal("one failure on probation must eject again")
	}

	// A success on probation clears it completely.
	now = now.Add(10 * time.Second)
	p.isEjected(ep)
	p.recordSuccess(ep)
	if ejected, _ := p.recordFailure(ep); ejected {
		t.Fatal("after a success, one failure must not eject")
	}
}

func TestPassiveHealthDisabled(t *testing.T) {
	p := newPassiveHealth(1, time.Minute)
	const ep = "http://a:8080"
	p.recordFailure(ep)
	if !p.isEjected(ep) {
		t.Fatal("expected ejection with maxFails=1")
	}
	p.configure(1, time.Minute, false)
	if p.isEjected(ep) {
		t.Fatal("disabling must forget existing ejections")
	}
	if ejected, _ := p.recordFailure(ep); ejected || p.isEjected(ep) {
		t.Fatal("a disabled registry must not eject")
	}
}

func TestPassiveHealthConfigDefaults(t *testing.T) {
	p := newPassiveHealth(0, 0)
	if p.maxFails != defaultPassiveMaxFails || p.ejectFor != defaultPassiveEjectFor {
		t.Fatalf("got maxFails=%d ejectFor=%v, want the defaults", p.maxFails, p.ejectFor)
	}
}

func TestIsBackendUnreachable(t *testing.T) {
	_, dialErr := net.Dial("tcp", deadEndpoint(t)[len("http://"):])
	if dialErr == nil {
		t.Fatal("expected the dial to fail")
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"refused dial", dialErr, true},
		{"wrapped refused dial", fmt.Errorf("proxy: %w", dialErr), true},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"client cancelled", context.Canceled, false},
		{"wrapped cancel", fmt.Errorf("proxy: %w", context.Canceled), false},
		{"other", errors.New("boom"), false},
		{"nil", nil, false},
	} {
		if got := isBackendUnreachable(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A request the client already abandoned must not count against the backend.
func TestRecordBackendFailureIgnoresCancelledRequests(t *testing.T) {
	resetPassiveHealth(t)
	passiveBackendHealth.configure(1, time.Minute, true)
	const ep = "http://a:8080"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recordBackendFailure(ctx, ep, io.ErrUnexpectedEOF)
	if passiveBackendHealth.isEjected(ep) {
		t.Fatal("a cancelled request ejected the backend")
	}
}

func TestSelectionSkipsEjectedBackend(t *testing.T) {
	resetPassiveHealth(t)
	backends := Backends{
		{Endpoint: "http://a:8080", Weight: 50},
		{Endpoint: "http://b:8080", Weight: 50},
	}
	passiveBackendHealth.configure(1, time.Minute, true)
	passiveBackendHealth.recordFailure("http://a:8080")

	for i := 0; i < 50; i++ {
		if b := backends.SelectBackend(); b == nil || b.Endpoint != "http://b:8080" {
			t.Fatalf("weighted selection picked %v, want http://b:8080", b)
		}
		if b := backends.getNextAvailableBackend(backends.availableBackendCount()); b == nil || b.Endpoint != "http://b:8080" {
			t.Fatalf("round-robin selection picked %v, want http://b:8080", b)
		}
	}
}

// With every backend ejected, the route must keep trying them rather than
// answer 503 for the whole cooldown.
func TestSelectionIgnoresEjectionsWhenAllAreEjected(t *testing.T) {
	resetPassiveHealth(t)
	backends := Backends{
		{Endpoint: "http://a:8080", Weight: 50},
		{Endpoint: "http://b:8080", Weight: 50},
	}
	passiveBackendHealth.configure(1, time.Minute, true)
	passiveBackendHealth.recordFailure("http://a:8080")
	passiveBackendHealth.recordFailure("http://b:8080")

	if backends.SelectBackend() == nil {
		t.Fatal("weighted selection returned nothing with every backend ejected")
	}
	if n := backends.availableBackendCount(); n != 2 {
		t.Fatalf("availableBackendCount = %d, want 2", n)
	}

	// An active-check failure still removes a backend outright.
	unavailableBackends.markUnavailable("http://b:8080")
	t.Cleanup(func() { unavailableBackends.markAvailable("http://b:8080") })
	for i := 0; i < 20; i++ {
		if b := backends.SelectBackend(); b == nil || b.Endpoint != "http://a:8080" {
			t.Fatalf("picked %v, want http://a:8080", b)
		}
	}
}

// End to end: with one live and one dead backend, only the first maxFails
// requests routed to the dead one fail, on every load-balancing strategy.
func TestProxyFailsOverFromDeadBackend(t *testing.T) {
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer live.Close()

	for _, tc := range []struct {
		name     string
		weighted bool
		canary   bool
	}{
		{name: "round-robin"},
		{name: "weighted", weighted: true},
		{name: "canary", canary: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetPassiveHealth(t)
			dead := deadEndpoint(t)
			backends := Backends{
				{Endpoint: dead, Weight: 50},
				{Endpoint: live.URL, Weight: 50},
			}
			if tc.canary {
				backends = append(backends, &Backend{
					Endpoint: deadEndpoint(t), Exclusive: true,
					Match: []BackendMatch{{Source: SourceTypeHeader, Name: "X-Never", Operator: OperatorEquals, Value: "1"}},
				})
			}
			pr := &ProxyRoute{name: "r", backends: backends, weightedBased: tc.weighted, canaryBased: tc.canary}
			handler := pr.ProxyHandler()
			before := ejections(t, dead)

			failed := 0
			for i := 0; i < 100; i++ {
				rec := httptest.NewRecorder()
				handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
				if rec.Code != http.StatusOK {
					failed++
				}
			}
			if failed == 0 || failed > defaultPassiveMaxFails {
				t.Fatalf("%d of 100 requests failed, want between 1 and %d", failed, defaultPassiveMaxFails)
			}
			if got := ejections(t, dead) - before; got != 1 {
				t.Fatalf("ejection metric rose by %v, want 1", got)
			}
		})
	}
}

func TestPassiveHealthCheckConfigFromYAML(t *testing.T) {
	var g Gateway
	if err := yaml.Unmarshal([]byte("networking:\n  passiveHealthCheck:\n    maxFails: 3\n    ejectFor: 30s\nroutes: []\n"), &g); err != nil {
		t.Fatal(err)
	}
	if got := g.Networking.PassiveHealthCheck; !got.Enabled || got.MaxFails != 3 || got.EjectFor != "30s" {
		t.Fatalf("got %+v, want enabled by default with maxFails=3 ejectFor=30s", got)
	}

	g = Gateway{}
	if err := yaml.Unmarshal([]byte("routes: []\n"), &g); err != nil {
		t.Fatal(err)
	}
	if !g.Networking.PassiveHealthCheck.Enabled {
		t.Fatal("passive health checks must be on when not configured")
	}

	g = Gateway{}
	if err := yaml.Unmarshal([]byte("networking:\n  passiveHealthCheck:\n    enabled: false\nroutes: []\n"), &g); err != nil {
		t.Fatal(err)
	}
	if g.Networking.PassiveHealthCheck.Enabled {
		t.Fatal("enabled: false must turn passive health checks off")
	}
}
