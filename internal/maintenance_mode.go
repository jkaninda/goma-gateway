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
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"net/http"
)

type Maintenance struct {
	Enabled    bool   `yaml:"enabled"`
	StatusCode int    `yaml:"statusCode,omitempty" default:"503"` // default HTTP 503
	Message    string `yaml:"message,omitempty" default:"Service temporarily unavailable"`
}

func (m *Maintenance) UnmarshalYAML(unmarshal func(interface{}) error) error {
	m.StatusCode = http.StatusServiceUnavailable
	m.Message = "Service temporarily unavailable"

	type tmp Maintenance
	if err := unmarshal((*tmp)(m)); err != nil {
		return err
	}
	if m.StatusCode == 0 {
		m.StatusCode = http.StatusServiceUnavailable
	}
	if m.Message == "" {
		m.Message = "Service temporarily unavailable"
	}
	return nil
}

func (m *Maintenance) MaintenanceMode(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Enabled {
			logger.Warn("Route in maintenance mode", "status", m.StatusCode, "client_ip", getRealIP(r), "method", r.Method, "host", r.Host, "url", r.URL.String())
			middlewares.RespondWithError(w, r, m.StatusCode, m.Message, nil, getContentType(r))
			return
		}
		next.ServeHTTP(w, r)
	})
}
