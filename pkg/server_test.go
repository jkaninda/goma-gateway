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

package pkg

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	err = initTestConfig(configFile)
	if err != nil {
		t.Fatal("Error init config:", err)
	}
	err = CheckConfig(configFile)
	if err != nil {
		t.Fatalf("Error checking config: %s", err.Error())
	}
	log.Println("Goma Gateway configuration file checked successfully")
}

func TestStart(t *testing.T) {
	TestInit(t)
	err := initTestConfig(configFile)
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
	ctx := context.Background()
	g := GatewayServer{}
	gatewayServer, err := g.Config(configFile, ctx)
	if err != nil {
		t.Error(err)
	}
	err = gatewayServer.Initialize()
	if err != nil {
		return
	}
	go func() {
		err = gatewayServer.Start()
		if err != nil {
			t.Error(err)
			return
		}
	}()
	// start mock server
	mockServer := startMockServer()
	defer func() {
		err := mockServer.Shutdown(ctx)
		if err != nil {
			t.Error("Error shutting down mock server:", err)
		}
	}()
	waitForMockServer()
	assertStatus(t, http.MethodGet, "http://localhost:8080/readyz", nil, nil, "", http.StatusOK)

	assertStatus(t, http.MethodGet, "http://localhost:8080/api/v1/books", nil, nil, "", http.StatusUnauthorized)
	assertStatus(t, http.MethodGet, "http://localhost:8080/api/v2/books", nil, nil, "", http.StatusOK)
	// Test Method Not Allowed
	assertStatus(t, http.MethodPost, "http://localhost:8080/api/v2/books", nil, strings.NewReader("Hello"), "", http.StatusMethodNotAllowed)

	assertStatus(t, http.MethodGet, "http://localhost:8080/api/v1/docs/", nil, nil, "", http.StatusForbidden)

	// Test basic auth request
	testBasicAuthRequest(t)

	shutdownMockServer(t, mockServer)
}

func testBasicAuthRequest(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:wrongpassword")),
	}
	// Test GET /api/v1 with Basic Auth
	assertStatus(t, http.MethodGet, "http://localhost:8080/api/v1/books", headers, nil, "application/json", http.StatusUnauthorized)
	headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin"))
	assertStatus(t, http.MethodGet, "http://localhost:8080/api/v1/books", headers, nil, "", http.StatusOK)
	assertStatus(t, http.MethodGet, "http://localhost:8080/api/v1/books", headers, nil, "", http.StatusOK)

}

func startMockServer() *http.Server {
	mRouter := mux.NewRouter()
	mRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, World!"))
	}).Methods(http.MethodGet)

	mRouter.HandleFunc("/api/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"books": [{"id": 1, "title": "Book One"}, {"id": 2, "title": "Book Two"}]}`))
	}).Methods(http.MethodGet)
	mRouter.HandleFunc("/api/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		body, _ := io.ReadAll(r.Body)
		_, _ = fmt.Fprintf(w, `{"message": "Book created", "data": %s}`, string(body))
	}).Methods(http.MethodPost)
	mRouter.HandleFunc("/api/v2/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"books": [{"id": 1, "title": "Book One"}, {"id": 2, "title": "Book Two"}]}`))
	}).Methods(http.MethodGet)
	mRouter.HandleFunc("/api/v2/books", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"books": [{"id": 1, "title": "Book One"}, {"id": 2, "title": "Book Two"}]}`))
	}).Methods(http.MethodPost)
	server := &http.Server{
		Addr:    ":9090",
		Handler: mRouter,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Could not listen on :9090: %v\n", err)
		}
	}()

	time.Sleep(1 * time.Second)

	return server
}
func shutdownMockServer(t *testing.T, mockServer *http.Server) {
	err := mockServer.Shutdown(context.Background())
	if err != nil {
		t.Error("Error shutting down mock server:", err)
	}

}
func waitForMockServer() {
	time.Sleep(1 * time.Second)
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
