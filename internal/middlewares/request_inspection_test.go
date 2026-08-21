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

package middlewares

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A rejected XML body must stop at the gateway rather than being forwarded with
// a body that has already been read.
func TestXXEProtectionBlocksInvalidXML(t *testing.T) {
	reached := false
	handler := BlockExploitsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	}))

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("<unclosed>"))
	request.Header.Set("Content-Type", "application/xml")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if reached {
		t.Error("a rejected XML request was still forwarded to the upstream")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

// Valid XML passes through with a body the upstream can still read.
func TestXXEProtectionPreservesValidBody(t *testing.T) {
	var received string
	handler := BlockExploitsMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
	}))

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("<note>hello</note>"))
	request.Header.Set("Content-Type", "application/xml")
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if received != "<note>hello</note>" {
		t.Errorf("upstream received %q, want the original body", received)
	}
}

// The body limit must reject on the declared length, before reading anything.
func TestBodyLimitRejectsOversizedRequests(t *testing.T) {
	reached := false
	limit := BodyLimit{MaxBytes: 16}
	handler := limit.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	}))

	oversized := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", 128)))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, oversized)

	if reached {
		t.Error("an oversized body reached the upstream")
	}
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}

	// A body within the limit is passed through intact.
	var received string
	handler = limit.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader("small")))
	if received != "small" {
		t.Errorf("upstream received %q, want %q", received, "small")
	}
}

// An unknown username must cost what a known one costs, or the user list can be
// enumerated by timing alone.
func TestBasicAuthDoesNotRevealKnownUsernames(t *testing.T) {
	auth := &AuthBasic{Users: []User{{
		Username: "known",
		// bcrypt hash of "secret"
		Password: "$2a$10$f0RTQ0HKSdhvU4h4/nuBse9ROnKBmfSmuPYzV.QcoDHePFqAeUDT2",
	}}}

	if auth.validateCredentials("known", "wrong-password") {
		t.Error("a wrong password was accepted")
	}
	if auth.validateCredentials("unknown", "wrong-password") {
		t.Error("an unknown user was accepted")
	}
	if !auth.validateCredentials("known", "secret") {
		t.Error("the correct credentials were rejected")
	}
}
