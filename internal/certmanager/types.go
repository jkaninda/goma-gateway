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

type CertificateManager struct {
	Provider CertProvider `yaml:"provider,omitempty"`
	Acme     Acme         `yaml:"acme,omitempty"`
	Vault    Vault        `yaml:"vault,omitempty"`
}
type Acme struct {
	Email         string        `yaml:"email"`
	DirectoryURL  string        `yaml:"directoryUrl,omitempty"`
	StorageFile   string        `yaml:"storageFile,omitempty"`
	TermsAccepted bool          `yaml:"termsAccepted,omitempty" default:"true"`
	ChallengeType ChallengeType `yaml:"challengeType,omitempty"`
	DnsProvider   DnsProvider   `yaml:"dnsProvider,omitempty"`
	Credentials   Credentials   `yaml:"credentials,omitempty"`
}

type Challenge struct {
	Type     ChallengeType `yaml:"type,omitempty"`
	Provider AcmeProvider  `yaml:"provider,omitempty"`
}
type Credentials struct {
	ApiToken string `yaml:"apiToken,omitempty" env:"GOMA_CREDENTIALS_API_TOKEN, overwrite"`
}
type ChallengeType string
type DnsProvider string
type AcmeProvider string
type CertProvider string
type Vault struct {
	Address string `yaml:"address,omitempty"`
	Token   string `yaml:"token,omitempty"`
	Role    string `yaml:"role,omitempty"`
}
