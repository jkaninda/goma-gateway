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
			writeReloadJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "error": "unauthorized"})
			return
		}
		start := time.Now()
		if err := g.reload(r); err != nil {
			logger.Error("On-demand reload failed", "error", err, "remote", req.RemoteAddr)
			writeReloadJSON(w, http.StatusInternalServerError, map[string]any{"status": "error", "error": err.Error()})
			return
		}
		ms := time.Since(start).Milliseconds()
		logger.Info("Configuration reloaded on demand", "routes", len(g.dynamicRoutes), "remote", req.RemoteAddr, "durationMs", ms)
		writeReloadJSON(w, http.StatusOK, map[string]any{"status": "ok", "routes": len(g.dynamicRoutes), "durationMs": ms})
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

func writeReloadJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
