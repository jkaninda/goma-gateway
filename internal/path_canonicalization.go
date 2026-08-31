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
	"net/http"
	"path"
	"strings"
)

// canonicalizePath normalises the request path once, at ingress, before any
// routing or middleware sees it.
//
// Without this the gateway and the upstream disagree about which resource is
// being requested: the auth middlewares match the raw, un-normalised
// r.URL.Path, while ReverseProxy forwards the escaped path verbatim to a
// backend that collapses "//", "/./" and "/x/../" itself. A rule guarding
// "/api/v1/users" was bypassed by asking for "/api/v1//users", which every
// common upstream resolves back to the guarded path.
//
// The normalised value is written back to both URL.Path and URL.RawPath so
// that matching, rewriting, cache keys and forwarding all use one string.
func canonicalizePath(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.URL.EscapedPath()

		// Encoded separators are ambiguous by construction: the gateway would
		// match them as opaque bytes and the upstream would decode them into
		// path structure. There is no safe interpretation, so refuse them.
		if hasEncodedSeparator(escaped) {
			logger.Warn("Rejected request with an encoded path separator",
				"path", escaped, "host", r.Host)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		cleaned := cleanURLPath(r.URL.Path)
		if cleaned == r.URL.Path {
			next.ServeHTTP(w, r)
			return
		}

		// Rewriting Path alone is not enough: RawPath keeps the original
		// escaping and is what EscapedPath — and therefore ReverseProxy —
		// forwards. Clearing it makes the cleaned Path authoritative.
		r.URL.Path = cleaned
		r.URL.RawPath = ""
		next.ServeHTTP(w, r)
	})
}

// hasEncodedSeparator reports whether an escaped path smuggles a separator or a
// dot segment through percent-encoding. "%2e" only counts when it decodes to a
// whole "." or ".." segment, so an encoded dot inside an ordinary filename
// still passes.
func hasEncodedSeparator(escaped string) bool {
	if !strings.Contains(escaped, "%") {
		return false
	}
	lower := strings.ToLower(escaped)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return true
	}
	if !strings.Contains(lower, "%2e") {
		return false
	}
	for _, segment := range strings.Split(lower, "/") {
		if !strings.Contains(segment, "%2e") {
			continue
		}
		if decoded := strings.ReplaceAll(segment, "%2e", "."); decoded == "." || decoded == ".." {
			return true
		}
	}
	return false
}

// cleanURLPath collapses duplicate slashes and resolves "." and ".." segments,
// preserving a trailing slash because routes may distinguish "/x" from "/x/".
func cleanURLPath(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := path.Clean(p)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	if cleaned != "/" && strings.HasSuffix(p, "/") {
		cleaned += "/"
	}
	return cleaned
}
