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

import (
	"errors"
	"sync"
	"time"
)

var (
	HTTP01 ChallengeType = "http-01"
	DNS01  ChallengeType = "dns-01"

	cloudflareProvider   DnsProvider  = "cloudflare"
	route53Provider      DnsProvider  = "route53"
	CertAcmeProvider     CertProvider = "acme"
	CertVaultProvider    CertProvider = "vault"
	acmeFile                          = "acme.json"
	cacheDir                          = "/etc/letsencrypt"
	ErrAlreadyInProgress              = errors.New("certificate renewal already in progress, please wait for the current process to finish")
	httpChallengeMu      sync.Mutex
)

const (
	httpChallengePort     = "5002"
	configVersion         = "1.0"
	gomaEnv               = "GOMA_ENV"
	local                 = "local"
	development           = "development"
	renewalCheckInterval  = 24 * time.Hour
	certificateBufferTime = 24 * time.Hour
	renewalBufferTime     = 30 * 24 * time.Hour // 30 days
	requestDelay          = 15 * time.Second
	errorDelay            = 20 * time.Second
	rsaKeySize            = 2048
)
