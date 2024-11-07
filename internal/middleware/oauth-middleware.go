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

package middleware

import (
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"golang.org/x/oauth2"
	"net/http"
)

func oauth2Config(oauth Oauth) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     oauth.ClientID,
		ClientSecret: oauth.ClientSecret,
		RedirectURL:  oauth.RedirectURL,
		Scopes:       oauth.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:       oauth.Endpoint.AuthURL,
			TokenURL:      oauth.Endpoint.TokenURL,
			DeviceAuthURL: oauth.Endpoint.DeviceAuthURL,
		},
	}
}
func (oauth Oauth) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("%s: %s Oauth", getRealIP(r), r.URL.Path)
		oauthConfig := oauth2Config(oauth)
		// Check if the user is authenticated
		_, err := r.Cookie("oauth-token")
		if err != nil {
			// If no token, redirect to OAuth provider
			url := oauthConfig.AuthCodeURL(oauth.State)
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
			return
		}
		//TODO: Check if the token stored in the cookie is valid

		// Token exists, proceed with request
		next.ServeHTTP(w, r)
	})
}