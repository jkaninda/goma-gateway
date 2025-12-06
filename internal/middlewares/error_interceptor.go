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

// ShouldIntercept checks if the given status code matches any of the route errors.
// If a match is found, it returns true along with the corresponding body or file to be used for the response.
func ShouldIntercept(status int, routeErrors []RouteError) (bool, string, bool) {
	for _, routeError := range routeErrors {
		if status == routeError.StatusCode || status == routeError.Status || status == routeError.Code {
			if routeError.Body != "" {
				return true, routeError.Body, false
			}
			if len(routeError.File) > 0 {
				return true, routeError.File, true
			}
			return true, fmt.Sprintf("%d %s", status, http.StatusText(status)), false
		}
	}
	return false, "", false
}
