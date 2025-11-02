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

package main

import (
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"github.com/jkaninda/logger"
	"net/http"
)

// MyPlugin is a custom middleware plugin
type MyPlugin struct {
	paths []string
	cfg   map[string]interface{}
}

// New is the exported constructor function
func New() plugins.Middleware {
	return &MyPlugin{}
}

func (m *MyPlugin) Name() string { return "myPlugin" }

// Configure initializes the middleware with configuration
func (m *MyPlugin) Configure(rule interface{}) error {
	if cfg, ok := rule.(map[string]interface{}); ok {
		m.cfg = cfg
		return nil
	}
	return fmt.Errorf("invalid config format")
}
func (m *MyPlugin) Validate() error {
	return nil
}

func (m *MyPlugin) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range m.paths {
			if r.URL.Path == p {
				fmt.Printf("Custom middleware triggered for path %s\n", r.URL.Path)
			}
		}
		mgs := m.cfg["message"]
		if mgs != nil {
			fmt.Printf("Custom message from config: %s\n", mgs)
		}
		logger.Info("Custom middleware triggered for path %s\n", "path", r.URL.Path, " plugin", m.Name(), "paths", m.paths)
		next.ServeHTTP(w, r)
	})
}

// WithPaths sets the paths for which this middleware should be applied
func (m *MyPlugin) WithPaths(paths []string) {
	m.paths = paths
}
