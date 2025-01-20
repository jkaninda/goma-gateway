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

func (oauth Oauth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPathMatching(r.URL.Path, oauth.Path, oauth.Paths) {
			oauthConf := oauth2Config(oauth)
			// Check if the user is authenticated
			token, err := r.Cookie("goma.oauth")
			if err != nil {
				// If no token, redirect to OAuth provider
				url := oauthConf.AuthCodeURL(oauth.State)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
				return
			}
			ok, err := validateJWT(token.Value, oauth.JWTSecret)
			if err != nil {
				// If no token, redirect to OAuth provider
				url := oauthConf.AuthCodeURL(oauth.State)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
				return
			}
			if !ok {
				// If no token, redirect to OAuth provider
				url := oauthConf.AuthCodeURL(oauth.State)
				http.Redirect(w, r, url, http.StatusTemporaryRedirect)
				return
			}
		}
		// Token exists, proceed with request
		next.ServeHTTP(w, r)
	})
}
