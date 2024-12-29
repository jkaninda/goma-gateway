package middlewares

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
import (
	"fmt"
	"net/http"
)

func CanIntercept(status int, routeErrors []RouteError) (bool, string) {
	for _, routeError := range routeErrors {
		if status == routeError.Status || status == routeError.Code {
			if routeError.Body != "" {
				return true, routeError.Body
			}
			return true, fmt.Sprintf("%d %s", status, http.StatusText(status))
		}
	}
	return false, ""
}
