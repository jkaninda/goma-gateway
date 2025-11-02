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
	"net/http"
	"strings"
)

type UserAgentBlock struct {
	UserAgents []string
}

// Middleware blocks requests from disallowed user agents (bots).
func (b UserAgentBlock) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(b.UserAgents) == 0 {
			logger.Warn(">> UserAgentBlock: no user agents configured to block")
			next.ServeHTTP(w, r)
			return
		}

		userAgent := r.Header.Get("User-Agent")
		contentType := getContentType(r)
		clientIP := realIP(r)
		requestPath := r.URL.Path

		for _, blockedAgent := range b.UserAgents {
			if strings.Contains(userAgent, blockedAgent) {
				logger.Warn(
					"Blocked request",
					"ip", clientIP,
					"path", requestPath,
					"userAgent", userAgent,
					"reason", "user agent not allowed",
				)
				RespondWithError(w, r, http.StatusForbidden, "User agent not allowed", nil, contentType)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
