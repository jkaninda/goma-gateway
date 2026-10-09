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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthCheckURL(t *testing.T) {
	for _, tc := range []struct{ endpoint, path, want string }{
		{"http://a:8080", "/health", "http://a:8080/health"},
		{"http://a:8080/", "/health", "http://a:8080/health"},
		{"http://a:8080/api/", "health", "http://a:8080/api/health"},
		{"http://a:8080", "", "http://a:8080"},
	} {
		if got := healthCheckURL(tc.endpoint, tc.path); got != tc.want {
			t.Errorf("healthCheckURL(%q, %q) = %q, want %q", tc.endpoint, tc.path, got, tc.want)
		}
	}
}

func TestHealthCheckDefaultsTimeout(t *testing.T) {
	route := Route{Name: "r", Enabled: true, Target: "http://a:8080", HealthCheck: RouteHealthCheck{Path: "/health"}}
	checks := healthCheckRoutes([]Route{route})
	if len(checks) != 1 || checks[0].TimeOut != defaultHealthCheckTimeout {
		t.Fatalf("expected one check with the default timeout, got %+v", checks)
	}
}

func TestUnhealthyBackendsWithPathAreTakenOutOfRotation(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()

	backends := Backends{
		{Endpoint: down.URL + "/api/", Weight: 50},
		{Endpoint: down.URL + "/v2", Weight: 50},
	}
	route := Route{Name: "r", Enabled: true, Backends: backends, HealthCheck: RouteHealthCheck{Path: "/health"}}
	for _, check := range healthCheckRoutes([]Route{route}) {
		check.run()
		t.Cleanup(func() { unavailableBackends.markAvailable(check.Endpoint) })
	}
	for _, b := range backends {
		if !backends.isUnavailable(b) {
			t.Errorf("backend %q failed its health check but is still in rotation", b.Endpoint)
		}
	}

	// With every backend down, the route must answer 503 rather than panic.
	pr := &ProxyRoute{name: "r", backends: backends, weightedBased: true}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, _, err := pr.createProxy(req, "", rec); err == nil {
		t.Fatal("expected an error when no backend is available")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	pr = &ProxyRoute{name: "r", backends: backends}
	rec = httptest.NewRecorder()
	if _, _, err := pr.createProxy(req, "", rec); err == nil || rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("round-robin: err = %v, status = %d, want an error and %d", err, rec.Code, http.StatusServiceUnavailable)
	}
}

func TestRouteHealthHandlerIncludeErrors(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer down.Close()
	names := []string{"a", "b", "c", "d"}
	routes := make([]Route, 0, len(names))
	for _, name := range names {
		routes = append(routes, Route{Name: name, Enabled: true, Target: down.URL, HealthCheck: RouteHealthCheck{Path: "/health"}})
	}
	for _, include := range []bool{true, false} {
		rec := httptest.NewRecorder()
		HealthCheckRoute{IncludeErrors: include, Routes: routes}.HealthCheckHandler(rec, httptest.NewRequest(http.MethodGet, "/healthz/routes", nil))
		body := rec.Body.String()
		if got := strings.Contains(body, "Error: "); got != include {
			t.Errorf("includeErrors=%v: response contains error details = %v:\n%s", include, got, body)
		}
		if n := strings.Count(body, `"unhealthy"`); n != len(routes) {
			t.Errorf("includeErrors=%v: %d unhealthy routes reported, want %d", include, n, len(routes))
		}
	}
}
