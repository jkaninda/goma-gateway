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
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// registerReloadHandler exposes the token-protected on-demand reload endpoint.
// It lets an external controller (e.g. Miabi) tell the gateway to pull and apply
// its configuration immediately instead of waiting for the provider poll
// interval. The endpoint is only registered when it is enabled and a token is
// configured, so it is never exposed unauthenticated.
func (g *Goma) registerReloadHandler(router *mux.Router, r Router) {
	cfg := g.gateway.Reload
	token := cfg.reloadToken()
	if !cfg.Enabled || token == "" {
		if cfg.Enabled && token == "" {
			logger.Warn("Reload endpoint enabled but no token configured; endpoint not registered")
		}
		return
	}

	path := cfg.reloadPath()
	handler := func(w http.ResponseWriter, req *http.Request) {
		if !validReloadToken(req, token) {
			writeReloadError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		start := time.Now()
		if err := g.reload(r); err != nil {
			logger.Error("On-demand reload failed", "error", err, "remote", req.RemoteAddr)
			writeReloadError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ms := time.Since(start).Milliseconds()
		logger.Info("Configuration reloaded on demand", "routes", len(g.dynamicRoutes), "remote", req.RemoteAddr, "durationMs", ms)
		writeReloadStatus(w, http.StatusOK, "ok", map[string]any{"routes": len(g.dynamicRoutes), "durationMs": ms})
	}

	route := router.HandleFunc(path, handler).Methods(http.MethodPost)
	if cfg.Host != "" {
		route.Host(cfg.Host)
	}
	logger.Debug("Reload endpoint registered", "path", path, "host", cfg.Host)
}

// validReloadToken validates the "Authorization: Bearer <token>" header against
// the configured token using a constant-time comparison.
func validReloadToken(req *http.Request, token string) bool {
	const prefix = "Bearer "
	header := req.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

// writeReloadStatus writes a JSON response carrying a "status" field plus any
// extra body fields.
func writeReloadStatus(w http.ResponseWriter, httpStatus int, status string, body map[string]any) {
	if body == nil {
		body = map[string]any{}
	}
	body["status"] = status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(body)
}

// writeReloadError writes a JSON error response with the given message.
func writeReloadError(w http.ResponseWriter, httpStatus int, msg string) {
	writeReloadStatus(w, httpStatus, "error", map[string]any{"error": msg})
}
