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
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
)

// OAuth provider identifiers.
const (
	ProviderCustom   = "custom"
	ProviderGoogle   = "google"
	ProviderGitHub   = "github"
	ProviderGitLab   = "gitlab"
	ProviderAmazon   = "amazon"
	ProviderFacebook = "facebook"
)

func oauth2Config(oauth *Oauth) *oauth2.Config {
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
	case ProviderGoogle:
		config.Endpoint = google.Endpoint
	case ProviderAmazon:
		config.Endpoint = amazon.Endpoint
	case ProviderFacebook:
		config.Endpoint = facebook.Endpoint
	case ProviderGitHub:
		config.Endpoint = github.Endpoint
	case ProviderGitLab:
		config.Endpoint = gitlab.Endpoint
	default:
		if oauth.Provider != ProviderCustom {
			logger.Error("Unknown provider,", "provider", oauth.Provider)
		}

	}
	return config
}
