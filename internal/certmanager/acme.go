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

package certmanager

type Acme struct {
	Email         string    `yaml:"email,omitempty"`
	DirectoryURL  string    `yaml:"directoryURL,omitempty"`
	Storage       string    `yaml:"storage,omitempty"`
	TermsAccepted bool      `yaml:"termsAccepted,omitempty"`
	Challenge     Challenge `yaml:"challenge,omitempty"`
}

type Challenge struct {
	Type        ChallengeType `yaml:"type,omitempty"`
	Provider    ProviderType  `yaml:"provider,omitempty"`
	Credentials Credentials   `yaml:"credentials,omitempty"`
}
type Credentials struct {
	ApiToken string `yaml:"apiToken,omitempty" env:"GOMA_CREDENTIALS_API_TOKEN, overwrite"`
}
type ChallengeType string
type ProviderType string

var (
	HTTP01 ChallengeType = "http-01"
	DNS01  ChallengeType = "dns-01"

	cloudflareProvider ProviderType = "cloudflare"
	Route53Provider    ProviderType = "route53"
	acmeFile                        = "acme.json"
)

const (
	cacheDir          = "/etc/goma/certs"
	httpChallengePort = "5002"
)
