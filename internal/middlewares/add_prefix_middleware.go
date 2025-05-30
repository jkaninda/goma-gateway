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
	"github.com/jkaninda/goma-gateway/internal/logger"
	"github.com/jkaninda/goma-gateway/util"
	"net/http"
	"strings"
)

type AddPrefix struct {
	Prefix string
	Path   string
}

// AddPrefixMiddleware updates the path of a request before forwarding it.
func (p *AddPrefix) AddPrefixMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.Prefix == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Update the request path
		originalPath := r.URL.Path
		// Log the prefix addition process
		logger.Debug("Adding prefix to the route")

		// Build the new path
		newPath := p.Prefix
		// Append the original path
		if !strings.HasSuffix(p.Path, "/") {
			newPath += strings.TrimPrefix(r.URL.Path, "/")
		}
		r.URL.Path = util.ParseURLPath(newPath)
		// Log the path rewrite
		logger.Debug("Rewriting Path from %s to %s", originalPath, r.URL.Path)
		// Proceed to the next handler
		next.ServeHTTP(w, r)
	})
}
