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

// StripQuery removes named query parameters from a request before it is
// forwarded upstream.
//
// It exists for the case where a parameter is an OPTIONAL hint the backend would
// act on, but which the gateway is not willing to let through. Denying the whole
// request is the wrong answer there: the client asked for something valid and
// merely offered an optimization, so the right move is to drop the hint and let
// the request proceed.
//
// The motivating case is a Docker registry's cross-repository blob mount
// (`POST /v2/<name>/blobs/uploads/?mount=<digest>&from=<other-repo>`). The client
// is telling the registry it can link an existing layer instead of uploading it.
// When the credential has no rights to <other-repo>, refusing the request fails
// the entire push — a docker client reads 403 on that POST as an auth failure and
// gives up. Stripping `mount` and `from` turns it into an ordinary upload, which
// is exactly what the distribution spec prescribes for a mount that cannot be
// satisfied.
type StripQuery struct {
	// Params are the query parameter names to remove.
	Params []string
	// Methods optionally limits the middleware to these HTTP methods
	// (case-insensitive). Empty applies to every method.
	Methods []string
	// PathPattern optionally limits the middleware to request paths matching this
	// regular expression. Empty applies to every path. An invalid pattern matches
	// nothing, so a typo disables the rule rather than silently widening it.
	PathPattern string

	re     *regexp.Regexp
	reInit bool
}

// StripQueryMiddleware removes the configured parameters from matching requests.
func (s *StripQuery) StripQueryMiddleware(next http.Handler) http.Handler {
	// Compile once; a bad pattern is reported by the caller at config time.
	if !s.reInit {
		s.reInit = true
		if s.PathPattern != "" {
			s.re, _ = regexp.Compile(s.PathPattern)
		}
	}
	methods := make(map[string]bool, len(s.Methods))
	for _, m := range s.Methods {
		methods[strings.ToUpper(strings.TrimSpace(m))] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.applies(r, methods) {
			next.ServeHTTP(w, r)
			return
		}
		q := r.URL.Query()
		stripped := false
		for _, p := range s.Params {
			if q.Has(p) {
				q.Del(p)
				stripped = true
			}
		}
		if stripped {
			r.URL.RawQuery = q.Encode()
			// RequestURI is what a reverse proxy may re-derive the outbound request
			// from; leaving the original there would forward what we just removed.
			if r.RequestURI != "" {
				r.RequestURI = r.URL.RequestURI()
			}
			logger.Debug("Stripped query parameters", "path", r.URL.Path, "params", s.Params)
		}
		next.ServeHTTP(w, r)
	})
}

// applies reports whether this request is in scope for the rule.
func (s *StripQuery) applies(r *http.Request, methods map[string]bool) bool {
	if len(methods) > 0 && !methods[strings.ToUpper(r.Method)] {
		return false
	}
	if s.PathPattern != "" {
		if s.re == nil {
			return false // unparseable pattern → match nothing
		}
		return s.re.MatchString(r.URL.Path)
	}
	return true
}
