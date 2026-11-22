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

	"gopkg.in/yaml.v3"
)

func serveMaintenance(t *testing.T, m *Maintenance, accept string) *httptest.ResponseRecorder {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	m.MaintenanceMode(next).ServeHTTP(rec, req)
	return rec
}

func TestMaintenanceHTML(t *testing.T) {
	page := "<!doctype html><title>Back soon</title><h1>Back soon</h1>"
	m := &Maintenance{Enabled: true, StatusCode: http.StatusServiceUnavailable, Message: "Back soon", HTML: page}

	rec := serveMaintenance(t, m, "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("browser status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("browser content type = %q", ct)
	}
	if rec.Body.String() != page {
		t.Fatalf("browser body = %q", rec.Body.String())
	}

	rec = serveMaintenance(t, m, "application/json")
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("json content type = %q", ct)
	}
	if strings.Contains(rec.Body.String(), "<h1>") || !strings.Contains(rec.Body.String(), "Back soon") {
		t.Fatalf("json body = %q", rec.Body.String())
	}

	rec = serveMaintenance(t, m, "")
	if strings.Contains(rec.Body.String(), "<h1>") {
		t.Fatalf("no Accept should not get the page: %q", rec.Body.String())
	}
}

func TestMaintenanceWithoutHTMLKeepsMessage(t *testing.T) {
	m := &Maintenance{Enabled: true, StatusCode: http.StatusServiceUnavailable, Message: "Back soon"}
	rec := serveMaintenance(t, m, "text/html,*/*")
	if rec.Code != http.StatusServiceUnavailable || strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "Back soon") {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestMaintenanceDisabledPassesThrough(t *testing.T) {
	m := &Maintenance{HTML: "<h1>x</h1>"}
	if rec := serveMaintenance(t, m, "text/html"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestMaintenanceHTMLFromYAML(t *testing.T) {
	var m Maintenance
	doc := "enabled: true\nhtml: |\n  <h1>Back soon</h1>\n"
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatal(err)
	}
	if m.HTML != "<h1>Back soon</h1>\n" || m.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %+v", m)
	}
	if keys := unknownKeys([]byte("maintenance:\n  enabled: true\n  html: x\n"), &Route{}); len(keys) != 0 {
		t.Fatalf("html reported unknown: %v", keys)
	}
}
