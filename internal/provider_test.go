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
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPProvider_JSON(t *testing.T) {
	bundle := &ConfigBundle{
		Version: "1.0.0",
		Routes: []Route{
			{
				Name:    "test-route",
				Path:    "/test",
				Methods: []string{"GET"},
				Target:  "https://example.com",
				Enabled: true,
			},
		},
		Middlewares: []Middleware{},
		Metadata:    map[string]string{},
		Timestamp:   time.Now(),
	}
	bundle.Checksum = bundle.CalculateChecksum()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(bundle)
		if err != nil {
			return
		}
	}))
	defer server.Close()

	provider, err := NewHTTPProvider(&HTTPProvider{
		Enabled:  true,
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
	})

	assert.NoError(t, err)

	ctx := context.Background()
	loaded, err := provider.Load(ctx)

	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", loaded.Version)
	assert.Len(t, loaded.Routes, 1)
	assert.Equal(t, "test-route", loaded.Routes[0].Name)
}

func TestHTTPProvider_YAML(t *testing.T) {
	bundle := &ConfigBundle{
		Version: "1.0.0",
		Routes: []Route{
			{
				Name:    "test-route",
				Path:    "/test",
				Methods: []string{"GET"},
				Target:  "https://example.com",
				Enabled: true,
			},
		},
		Middlewares: []Middleware{},
		Metadata:    map[string]string{},
		Timestamp:   time.Now(),
	}
	// bundle.Checksum = bundle.CalculateChecksum()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		err := yaml.NewEncoder(w).Encode(bundle)
		if err != nil {
			return
		}
	}))
	defer server.Close()

	provider, err := NewHTTPProvider(&HTTPProvider{
		Enabled:  true,
		Endpoint: server.URL,
		Timeout:  5 * time.Second,
	})

	assert.NoError(t, err)

	ctx := context.Background()
	loaded, err := provider.Load(ctx)

	assert.NoError(t, err)
	assert.Equal(t, "1.0.0", loaded.Version)
	assert.Len(t, loaded.Routes, 1)
	assert.Equal(t, "test-route", loaded.Routes[0].Name)
}

func TestHTTPProvider_AutoDetect(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		expectError bool
	}{
		{
			name:        "JSON with content type",
			contentType: "application/json",
			body:        `{"version":"1.0.0","routes":[],"middlewares":[]}`,
			expectError: false,
		},
		{
			name:        "YAML with content type",
			contentType: "application/yaml",
			body:        "version: 1.0.0\nroutes: []\nmiddlewares: []",
			expectError: false,
		},
		{
			name:        "JSON without content type",
			contentType: "",
			body:        `{"version":"1.0.0","routes":[],"middlewares":[]}`,
			expectError: false,
		},
		{
			name:        "YAML without content type",
			contentType: "",
			body:        "version: 1.0.0\nroutes: []\nmiddlewares: []",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.contentType != "" {
					w.Header().Set("Content-Type", tt.contentType)
				}
				_, err := w.Write([]byte(tt.body))
				if err != nil {
					return
				}
			}))
			defer server.Close()

			provider, err := NewHTTPProvider(&HTTPProvider{
				Enabled:  true,
				Endpoint: server.URL,
				Timeout:  5 * time.Second,
			})

			assert.NoError(t, err)

			ctx := context.Background()
			_, err = provider.Load(ctx)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
