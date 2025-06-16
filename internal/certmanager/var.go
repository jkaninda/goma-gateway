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

var (
	HTTP01 ChallengeType = "http-01"
	DNS01  ChallengeType = "dns-01"

	cloudflareProvider DnsProvider  = "cloudflare"
	route53Provider    DnsProvider  = "route53"
	CertAcmeProvider   CertProvider = "acme"
	CertVaultProvider  CertProvider = "vault"
	acmeFile                        = "acme.json"
	cacheDir                        = "/etc/letsencrypt"
)

const (
	httpChallengePort = "5002"
	configVersion     = "1.0"
)
