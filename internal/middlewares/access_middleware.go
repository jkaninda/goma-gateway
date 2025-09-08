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

// AccessMiddleware checks if the request path is forbidden and returns 403 Forbidden
func (blockList AccessListMiddleware) AccessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := getContentType(r)
		if isPathMatching(r.URL.Path, blockList.Path, blockList.Paths) {
			logger.Warn("%s: %s access forbidden", getRealIP(r), r.URL.Path)
			// Using custom StatusCode Code
			if blockList.StatusCode > 0 {
				RespondWithError(w, r, blockList.StatusCode, "", blockList.Origins, contentType)
				return

			}
			RespondWithError(w, r, http.StatusForbidden, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), blockList.Origins, contentType)
			return

		}
		next.ServeHTTP(w, r)
	})
}
