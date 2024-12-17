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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"net/http"
)

type AddPrefix struct {
	Prefix string
}

// AddPrefixMiddleware updates the path of a request before forwarding it.
func (rl *AddPrefix) AddPrefixMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("Adding prefix to the route")
		if rl.Prefix != "" {
			path := r.URL.Path
			r.URL.Path = util.ParseURLPath(rl.Prefix + path)
			logger.Debug("Old path: %s | New path: %s", path, r.URL.Path)
		}
		// Proceed to the next handler if requests limit is not exceeded
		next.ServeHTTP(w, r)
	})
}
