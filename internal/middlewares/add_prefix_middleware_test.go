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
	"net/http/httptest"
	"testing"
)

func TestAddPrefix(t *testing.T) {
	for _, tc := range []struct{ prefix, path, want string }{
		{"/prefix", "/api/resource", "/prefix/api/resource"},
		{"/prefix/", "/api/resource", "/prefix/api/resource"},
		{"/prefix", "/", "/prefix/"},
		{"/v1/internal", "/users", "/v1/internal/users"},
	} {
		var got string
		p := &AddPrefix{Prefix: tc.prefix}
		h := p.AddPrefixMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.URL.Path }))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.path, nil))
		if got != tc.want {
			t.Errorf("prefix %q + %q = %q, want %q", tc.prefix, tc.path, got, tc.want)
		}
	}
}
