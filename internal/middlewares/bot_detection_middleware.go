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
	"net/http"
	"strings"
)

type BotDetection struct {
	UserAgents []string `yaml:"userAgents"`
}

// BotDetectionMiddleware checks if the request is from a bot
func (botDetection BotDetection) BotDetectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		botDetection.UserAgents = append(botDetection.UserAgents, botUserAgents...)
		contentType := r.Header.Get("Content-Type")
		userAgent := r.Header.Get("User-Agent")
		for _, bot := range botDetection.UserAgents {
			if strings.Contains(userAgent, bot) {
				logger.Error("%s: %s Forbidden - Bots are not allowed", getRealIP(r), r.URL.Path)
				RespondWithError(w, r, http.StatusForbidden, "Bots are not allowed", nil, contentType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
