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
	"net/url"
	"regexp"
	"strings"
)

// tokenRegex matches {{goma.<source>.<name>}} placeholders in a rewrite
// replacement, capturing the source ("headers" or "query") and the name.
var tokenRegex = regexp.MustCompile(`\{\{\s*goma\.(headers|query)\.([A-Za-z0-9_-]+)\s*\}\}`)

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

		// Expand {{goma.headers.<Name>}} and {{goma.query.<Name>}} placeholders
		// from the incoming request (done after the regex replace so a value
		// containing $1 is not treated as a group reference).
		rewrittenURL = injectTokens(rewrittenURL, r.Header, r.URL.Query())

		r.URL.Path = rewrittenURL

		// Ensure the URL is properly formatted
		r.URL.RawPath = rewrittenURL

		logger.Debug("Rewriting URL", "from", originalURL, "to", rewrittenURL)
		next.ServeHTTP(w, r)
	})
}

// injectTokens replaces {{goma.headers.<Name>}} and {{goma.query.<Name>}}
// placeholders with the matching incoming request header or query value (empty
// string when absent). Values are path-escaped so an attacker-controlled header
// or query value expands to a single path segment and cannot inject additional
// path structure (e.g. "../" traversal or extra "/" separators).
func injectTokens(s string, headers http.Header, query url.Values) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return tokenRegex.ReplaceAllStringFunc(s, func(match string) string {
		m := tokenRegex.FindStringSubmatch(match)
		source, name := m[1], m[2]

		var value string
		switch source {
		case "headers":
			value = headers.Get(name)
		case "query":
			value = query.Get(name)
		}
		return url.PathEscape(value)
	})
}
