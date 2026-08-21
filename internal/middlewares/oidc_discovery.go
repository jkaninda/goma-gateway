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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	discoveryPath     = "/.well-known/openid-configuration"
	discoveryCacheTTL = time.Hour
	// discoveryErrorTTL keeps a failed lookup from being retried on every
	// request, which would put the provider's outage on the request path.
	discoveryErrorTTL = 30 * time.Second
	discoveryTimeout  = 10 * time.Second
	maxDiscoveryBytes = 1 << 20
)

// ProviderMetadata is the subset of the OpenID Connect discovery document the
// gateway uses.
type ProviderMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	UserInfoEndpoint              string   `json:"userinfo_endpoint"`
	JwksURI                       string   `json:"jwks_uri"`
	EndSessionEndpoint            string   `json:"end_session_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// SupportsPKCE reports whether the provider advertises S256 code challenges.
// An absent list is not a denial: the parameter is ignored by providers that do
// not implement it, and most that do still omit the metadata.
func (m *ProviderMetadata) SupportsPKCE() bool {
	if m == nil || len(m.CodeChallengeMethodsSupported) == 0 {
		return true
	}
	for _, method := range m.CodeChallengeMethodsSupported {
		if method == "S256" {
			return true
		}
	}
	return false
}

var discoveryStore = &discoveryCache{entries: make(map[string]*discoveryEntry)}

type discoveryCache struct {
	mu      sync.Mutex
	entries map[string]*discoveryEntry
}

type discoveryEntry struct {
	metadata  *ProviderMetadata
	err       error
	fetchedAt time.Time
}

// Discover reads the provider's OpenID Connect metadata, caching it for an hour.
//
// A provider that is briefly unreachable must not log everyone out, so a cached
// document keeps being served past its expiry when a refresh fails; only a cold
// cache turns a provider outage into an error.
func Discover(ctx context.Context, issuer string) (*ProviderMetadata, error) {
	if issuer == "" {
		return nil, fmt.Errorf("empty issuer")
	}
	key := strings.TrimSuffix(issuer, "/")

	discoveryStore.mu.Lock()
	cached := discoveryStore.entries[key]
	discoveryStore.mu.Unlock()

	if cached != nil {
		if cached.err != nil && time.Since(cached.fetchedAt) < discoveryErrorTTL {
			return nil, cached.err
		}
		if cached.err == nil && time.Since(cached.fetchedAt) < discoveryCacheTTL {
			return cached.metadata, nil
		}
	}

	metadata, err := fetchProviderMetadata(ctx, issuer)
	if err != nil {
		if cached != nil && cached.metadata != nil {
			logger.Warn("Failed to refresh OpenID Connect metadata, using the cached document",
				"issuer", issuer, "age", time.Since(cached.fetchedAt).String(), "error", err)
			return cached.metadata, nil
		}
		discoveryStore.mu.Lock()
		discoveryStore.entries[key] = &discoveryEntry{err: err, fetchedAt: time.Now()}
		discoveryStore.mu.Unlock()
		return nil, err
	}

	discoveryStore.mu.Lock()
	discoveryStore.entries[key] = &discoveryEntry{metadata: metadata, fetchedAt: time.Now()}
	discoveryStore.mu.Unlock()

	return metadata, nil
}

func fetchProviderMetadata(ctx context.Context, issuer string) (*ProviderMetadata, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	documentURL := strings.TrimSuffix(issuer, "/") + discoveryPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery document at %s returned %d", documentURL, response.StatusCode)
	}

	metadata := &ProviderMetadata{}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxDiscoveryBytes)).Decode(metadata); err != nil {
		return nil, fmt.Errorf("failed to decode the discovery document: %w", err)
	}

	// The issuer in the document must be the one we asked, or the document is
	// describing a different provider than the tokens will be checked against.
	if strings.TrimSuffix(metadata.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return nil, fmt.Errorf("discovery document issuer %q does not match the configured issuer %q",
			metadata.Issuer, issuer)
	}
	if metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document at %s is missing the authorization or token endpoint", documentURL)
	}

	return metadata, nil
}
