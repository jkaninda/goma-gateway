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
	"net/http"
	"regexp"
)

type RedirectRegex struct {
	Pattern     string
	Replacement string
}

// RedirectRegexMiddleware updates the path of a request before forwarding it.
func (regex *RedirectRegex) RedirectRegexMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		re := regexp.MustCompile(regex.Pattern)
		originalURL := r.URL.Path

		// Rewrite the path
		rewrittenURL := re.ReplaceAllString(originalURL, regex.Replacement)
		r.URL.Path = rewrittenURL

		// Ensure the URL is properly formatted
		r.URL.RawPath = rewrittenURL

		logger.Debug("Rewriting URL from %s to %s", originalURL, rewrittenURL)
		next.ServeHTTP(w, r)
	})
}
