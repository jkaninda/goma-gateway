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
	"fmt"
	"net/http"
)

// Misconfigured stands in for an access-control middleware whose rule could
// not be applied, rejecting every request so the route is never served
// without the protection it was configured with.
type Misconfigured struct {
	Origins []string
}

func (m Misconfigured) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		RespondWithError(w, r, http.StatusServiceUnavailable,
			fmt.Sprintf("%d %s", http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable)),
			m.Origins, getContentType(r))
	})
}
