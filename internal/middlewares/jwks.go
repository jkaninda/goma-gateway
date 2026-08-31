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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	jwksCacheTTL = time.Hour
	// jwksErrorTTL keeps a failed fetch off the request path for a while,
	// rather than retrying against a struggling identity provider once per
	// request.
	jwksErrorTTL = 30 * time.Second
	jwksTimeout  = 10 * time.Second
	maxJWKSBytes = 1 << 20
)

type Jwks struct {
	Keys []Jwk `json:"keys"`
}

type Jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Crv string `json:"crv"` // for EC
	X   string `json:"x"`   // for EC
	Y   string `json:"y"`   // for EC
}

var jwksStore = &jwksCache{entries: make(map[string]*jwksEntry)}

type jwksCache struct {
	mu      sync.Mutex
	entries map[string]*jwksEntry
}

type jwksEntry struct {
	// inFlight is held for the duration of a fetch so that a burst of requests
	// for a cold or stale key set produces one upstream call, not one per
	// request.
	inFlight  sync.Mutex
	keys      *Jwks
	err       error
	fetchedAt time.Time
}

// fetchJWKS returns the identity provider's key set, cached for an hour.
//
// This used to be a bare http.Get on http.DefaultClient, on every single
// request: no timeout, no status check, no body limit and no cache. Any
// unauthenticated caller could turn the gateway into an amplifier against the
// provider, and a black-holing JWKS host pinned a goroutine and a socket per
// in-flight request until the client gave up.
//
// As with OIDC discovery, a stale key set keeps being served when a refresh
// fails: a provider blip must not reject every token the gateway holds a valid
// key for.
func fetchJWKS(jwksURL string) (*Jwks, error) {
	if jwksURL == "" {
		return nil, fmt.Errorf("empty JWKS URL")
	}

	jwksStore.mu.Lock()
	entry := jwksStore.entries[jwksURL]
	if entry == nil {
		entry = &jwksEntry{}
		jwksStore.entries[jwksURL] = entry
	}
	jwksStore.mu.Unlock()

	if keys, err, ok := entry.fresh(); ok {
		return keys, err
	}

	entry.inFlight.Lock()
	defer entry.inFlight.Unlock()

	// Another request may have refreshed it while this one waited.
	if keys, err, ok := entry.fresh(); ok {
		return keys, err
	}

	keys, err := getJWKS(context.Background(), jwksURL)

	jwksStore.mu.Lock()
	defer jwksStore.mu.Unlock()
	if err != nil {
		if entry.keys != nil {
			logger.Warn("Failed to refresh the JWKS, using the cached key set",
				"url", jwksURL, "age", time.Since(entry.fetchedAt).String(), "error", err)
			return entry.keys, nil
		}
		entry.err, entry.fetchedAt = err, time.Now()
		return nil, err
	}
	entry.keys, entry.err, entry.fetchedAt = keys, nil, time.Now()
	return keys, nil
}

// fresh reports a cached result that is still within its TTL.
func (e *jwksEntry) fresh() (*Jwks, error, bool) {
	jwksStore.mu.Lock()
	defer jwksStore.mu.Unlock()
	switch {
	case e.err != nil && time.Since(e.fetchedAt) < jwksErrorTTL:
		return nil, e.err, true
	case e.keys != nil && time.Since(e.fetchedAt) < jwksCacheTTL:
		return e.keys, nil, true
	default:
		return nil, nil, false
	}
}

func getJWKS(ctx context.Context, jwksURL string) (*Jwks, error) {
	ctx, cancel := context.WithTimeout(ctx, jwksTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logger.Error("Error closing response body", "error", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %s", resp.Status)
	}

	var keySet Jwks
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&keySet); err != nil {
		return nil, err
	}
	return &keySet, nil
}

func (j *Jwks) getKey(kid string) (interface{}, error) {
	for _, key := range j.Keys {
		if key.Kid == kid {
			switch key.Kty {
			case "RSA":
				return parseRSAPublicKey(key.N, key.E)
			case "EC":
				return parseECDSAPublicKey(key.Crv, key.X, key.Y)
			default:
				return nil, fmt.Errorf("unsupported key type: %s", key.Kty)
			}
		}
	}
	return nil, fmt.Errorf("no matching JWK found for kid: %s", kid)
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	eInt := 0
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}
	return pubKey, nil
}

func parseECDSAPublicKey(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, err
	}

	var curve elliptic.Curve
	var coordinateSize int
	switch crv {
	case "P-256":
		curve, coordinateSize = elliptic.P256(), 32
	case "P-384":
		curve, coordinateSize = elliptic.P384(), 48
	case "P-521":
		curve, coordinateSize = elliptic.P521(), 66
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}

	if len(xBytes) > coordinateSize || len(yBytes) > coordinateSize {
		return nil, fmt.Errorf("EC coordinates are too long for curve %s", crv)
	}

	// Parsed as an uncompressed point rather than assembled from raw
	// coordinates: this checks that the point is actually on the curve, which
	// assigning X and Y directly does not.
	point := make([]byte, 1+2*coordinateSize)
	point[0] = 4 // uncompressed point marker
	copy(point[1+coordinateSize-len(xBytes):1+coordinateSize], xBytes)
	copy(point[1+2*coordinateSize-len(yBytes):], yBytes)

	pubKey, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, fmt.Errorf("invalid EC public key: %w", err)
	}
	return pubKey, nil
}
