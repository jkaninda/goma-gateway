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
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
)

func oauth2Config(oauth Oauth) *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     oauth.ClientID,
		ClientSecret: oauth.ClientSecret,
		RedirectURL:  oauth.RedirectURL,
		Scopes:       oauth.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oauth.Endpoint.AuthURL,
			TokenURL: oauth.Endpoint.TokenURL,
		},
	}
	switch oauth.Provider {
	case "google":
		config.Endpoint = google.Endpoint
	case "amazon":
		config.Endpoint = amazon.Endpoint
	case "facebook":
		config.Endpoint = facebook.Endpoint
	case "github":
		config.Endpoint = github.Endpoint
	case "gitlab":
		config.Endpoint = gitlab.Endpoint
	default:
		if oauth.Provider != "custom" {
			logger.Error("Unknown provider: %s", oauth.Provider)
		}

	}
	return config
}
