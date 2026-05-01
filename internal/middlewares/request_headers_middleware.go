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
)

// RequestHeaders rewrites the headers of the inbound request before it is
// forwarded to the upstream backend.
//
// Order: RemoveHeaders is applied first, then SetHeaders. An empty value in
// SetHeaders deletes the header (mirrors the response-side behavior).
//
// Paths/RoutePath gate which requests the rule applies to. When Paths is
// empty the rule runs for every request that reaches this middleware chain.
type RequestHeaders struct {
	Path          string
	Paths         []string
	SetHeaders    map[string]string
	RemoveHeaders []string
}

// Middleware returns the http.Handler middleware.
func (rh *RequestHeaders) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rh.appliesTo(r.URL.Path) {
			for _, name := range rh.RemoveHeaders {
				r.Header.Del(name)
			}
			for k, v := range rh.SetHeaders {
				if v == "" {
					r.Header.Del(k)
					continue
				}
				r.Header.Set(k, v)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (rh *RequestHeaders) appliesTo(urlPath string) bool {
	if len(rh.Paths) == 0 {
		return true
	}
	return isPathMatching(urlPath, rh.Path, rh.Paths)
}
