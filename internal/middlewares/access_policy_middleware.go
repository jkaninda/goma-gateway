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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"net"
	"net/http"
)

type AccessPolicy struct {
	Action       string
	SourceRanges []string
}

func (access AccessPolicy) AccessPolicyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iPs := make(map[string]struct{})
		for _, ip := range access.SourceRanges {
			iPs[ip] = struct{}{}
		}
		// Get the client's IP address
		ip, _, err := net.SplitHostPort(getRealIP(r))
		if err != nil {
			logger.Error("Unable to parse IP address")
			RespondWithError(w, http.StatusUnauthorized, "Unable to parse IP address")
			return
		}
		// Check if the IP is in the blocklist
		if access.Action == "DENY" {
			if _, ok := iPs[ip]; ok {
				logger.Error(" %s: IP address in the blocklist, access not allowed", getRealIP(r))
				RespondWithError(w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
				return
			}
		}
		// Check if the IP is in the allowlist
		if _, ok := iPs[ip]; !ok {
			logger.Error("%s: IP address not allowed ", getRealIP(r))
			RespondWithError(w, http.StatusForbidden, http.StatusText(http.StatusForbidden))
			return
		}
		// Continue to the next handler if the authentication is successful
		next.ServeHTTP(w, r)
	})

}
