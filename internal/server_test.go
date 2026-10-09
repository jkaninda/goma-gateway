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
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jkaninda/njia"
)

const testPath = "./tests"
const extraRoutePath = "./tests/extra"

var configFile = filepath.Join(testPath, "goma.yml")
var configFile2 = filepath.Join(testPath, "goma2.yml")

func TestInit(t *testing.T) {
	err := os.MkdirAll(testPath, os.ModePerm)
	if err != nil {
		t.Error(err)
	}
	err = os.MkdirAll(extraRoutePath, os.ModePerm)
	if err != nil {
		t.Error(err)
	}
}

func TestCheckConfig(t *testing.T) {
	TestInit(t)
	err := initConfig(configFile2)
	if err != nil {
		t.Fatal("Error init config:", err)
	}
	err = initTestConfig(configFile, "http://localhost:9090")
	if err != nil {
		t.Fatal("Error init config:", err)
	}
	err = CheckConfig(configFile)
	if err != nil {
		t.Fatalf("Error checking config: %s", err.Error())
	}
	log.Println("Goma Gateway configuration file checked successfully")
}

// TestStart runs the whole gateway in-process against a mock backend. It
// listens on free ports rather than 8080/8443, so it does not depend on what
// else is running on the machine, and it stops the gateway when it is done.
func TestStart(t *testing.T) {
	TestInit(t)
	mockServer := httptest.NewServer(mockBackend())
	defer mockServer.Close()

	webAddr := freeAddr(t)
	t.Setenv("GOMA_ENTRYPOINT_WEB_ADDRESS", webAddr)
	t.Setenv("GOMA_ENTRYPOINT_WEB_SECURE_ADDRESS", freeAddr(t))
	base := "http://" + webAddr

	err := initTestConfig(configFile, mockServer.URL)
	if err != nil {
		t.Fatalf("Error initializing config: %s", err.Error())
	}
	err = initExtraRoute(extraRoutePath)
	if err != nil {
		t.Fatalf("Error creating extra routes file: %s", err.Error())
	}
	err = CheckConfig(configFile)
	if err != nil {
		t.Fatalf("Error checking config: %s", err.Error())
	}
	g := Goma{}
	gatewayServer, err := g.Config(configFile, context.Background())
	if err != nil {
		t.Fatal(err)
	}

	stopped := make(chan error, 1)
	go func() { stopped <- gatewayServer.Start() }()
	defer stopGateway(t, stopped)
	waitForReady(t, base+"/readyz", stopped)

	assertStatus(t, http.MethodGet, base+"/readyz", nil, nil, "", http.StatusOK)

	assertStatus(t, http.MethodGet, base+"/api/v1/books", nil, nil, "", http.StatusUnauthorized)
	assertStatus(t, http.MethodGet, base+"/api/v2/books", nil, nil, "", http.StatusOK)
	// Test Method Not Allowed
	assertStatus(t, http.MethodPost, base+"/api/v2/books", nil, strings.NewReader("Hello"), "", http.StatusMethodNotAllowed)

	assertStatus(t, http.MethodGet, base+"/api/v1/docs/", nil, nil, "", http.StatusForbidden)

	// Test basic auth request
	testBasicAuthRequest(t, base)
}

func testBasicAuthRequest(t *testing.T, base string) {
	headers := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:wrongpassword")),
	}
	// Test GET /api/v1 with Basic Auth
	assertStatus(t, http.MethodGet, base+"/api/v1/books", headers, nil, "application/json", http.StatusUnauthorized)
	headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	assertStatus(t, http.MethodGet, base+"/api/v1/books", headers, nil, "", http.StatusOK)
	assertStatus(t, http.MethodGet, base+"/api/v1/books", headers, nil, "", http.StatusOK)

}

// freeAddr returns a loopback address with a port nothing is listening on.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// waitForReady polls url until it answers 200, failing early if the gateway
// stops instead.
func waitForReady(t *testing.T, url string, stopped <-chan error) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-stopped:
			t.Fatalf("gateway stopped before becoming ready: %v", err)
		default:
		}
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("gateway not ready at %s after 15s", url)
}

// stopGateway delivers a shutdown signal the way the OS would and waits for
// Start to return.
func stopGateway(t *testing.T, stopped <-chan error) {
	t.Helper()
	shutdownChan <- syscall.SIGTERM
	select {
	case err := <-stopped:
		if err != nil {
			t.Errorf("gateway shutdown: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Error("gateway did not stop within 15s of SIGTERM")
		return
	}
	// A gateway process starts and stops once, and shutdown closes these
	// single-use channels. Replace them so the test binary can start another
	// gateway (go test -count=N).
	stopChan = make(chan struct{})
	metricsStopChan = make(chan struct{})
}

func mockBackend() http.Handler {
	mRouter := njia.New()
	must := func(err error) {
		if err != nil {
			log.Fatalf("mock server route: %v", err)
		}
	}
	must(mRouter.HandleFunc(http.MethodGet, "/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, World!"))
	}))

	must(mRouter.HandleFunc(http.MethodGet, "/api/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"books": [{"id": 1, "title": "Book One"}, {"id": 2, "title": "Book Two"}]}`))
	}))
	must(mRouter.HandleFunc(http.MethodPost, "/api/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, `{"message": "Book created", "data": %s}`, string(body))
	}))
	must(mRouter.HandleFunc(http.MethodGet, "/api/v2/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"books": [{"id": 1, "title": "Book One"}, {"id": 2, "title": "Book Two"}]}`))
	}))
	must(mRouter.HandleFunc(http.MethodPost, "/api/v2/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"books": [{"id": 1, "title": "Book One"}, {"id": 2, "title": "Book Two"}]}`))
	}))
	return mRouter
}

func assertStatus(t *testing.T, method, url string,
	headers map[string]string,
	body io.Reader,
	contentType string,
	expected int) {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("Failed to create %s request to %s: %v", method, url, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to make %s request to %s: %v", method, url, err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			t.Errorf("Failed to close response body: %v", err)
		}
	}(resp.Body)

	if resp.StatusCode != expected {
		t.Errorf("Expected status %d for %s %s, got %d", expected, method, url, resp.StatusCode)
	}
}
