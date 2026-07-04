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
	"regexp"
	"strings"
)

// headerTokenRegex matches {{goma.headers.<HeaderName>}} placeholders in a
// rewrite replacement, capturing the header name.
var headerTokenRegex = regexp.MustCompile(`\{\{\s*goma\.headers\.([A-Za-z0-9-]+)\s*\}\}`)

type RewriteRegex struct {
	Pattern     string
	Replacement string
}

// RewriteRegexMiddleware updates the path of a request before forwarding it.
func (regex *RewriteRegex) RewriteRegexMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		re := regexp.MustCompile(regex.Pattern)
		originalURL := r.URL.Path

		// Rewrite the path (resolves regex group refs like $1)
		rewrittenURL := re.ReplaceAllString(originalURL, regex.Replacement)

		// Expand {{goma.headers.<Name>}} placeholders from incoming request
		// headers (done after the regex replace so a header value containing $1
		// is not treated as a group reference).
		rewrittenURL = injectHeaderTokens(rewrittenURL, r.Header)

		r.URL.Path = rewrittenURL

		// Ensure the URL is properly formatted
		r.URL.RawPath = rewrittenURL

		logger.Debug("Rewriting URL", "from", originalURL, "to", rewrittenURL)
		next.ServeHTTP(w, r)
	})
}

// injectHeaderTokens replaces {{goma.headers.<Name>}} placeholders with the
// matching incoming request header value (empty string when the header is
// absent).
func injectHeaderTokens(s string, headers http.Header) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return headerTokenRegex.ReplaceAllStringFunc(s, func(match string) string {
		name := headerTokenRegex.FindStringSubmatch(match)[1]
		return headers.Get(name)
	})
}
