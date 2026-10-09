/*
 * Copyright 2024 Jonas Kaninda — Apache-2.0
 */

package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStartPprofDisabledByDefault(t *testing.T) {
	if srv := startPprof(""); srv != nil {
		t.Fatal("pprof must not start without GOMA_PPROF_ADDR")
	}
}

func TestPprofHandlerServesProfiles(t *testing.T) {
	h := pprofHandler()
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/heap", "/debug/pprof/goroutine?debug=1"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("/: status %d, want 404", rec.Code)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:6060": true,
		"[::1]:6060":     true,
		"localhost:6060": true,
		":6060":          false,
		"0.0.0.0:6060":   false,
		"10.0.0.5:6060":  false,
		"bad":            false,
	} {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
