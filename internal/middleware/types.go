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
	"bytes"
	errorinterceptor "github.com/jkaninda/goma-gateway/pkg/errorinterceptor"
	"net/http"
	"sync"
	"time"
)

// RateLimiter defines rate limit properties.
type RateLimiter struct {
	Requests         int
	Window           time.Duration
	ClientMap        map[string]*Client
	mu               sync.Mutex
	Origins          []string
	ErrorInterceptor errorinterceptor.ErrorInterceptor
	RedisBased       bool
}

// Client stores request count and window expiration for each client.
type Client struct {
	RequestCount int
	ExpiresAt    time.Time
}

// NewRateLimiterWindow creates a new RateLimiter.
func NewRateLimiterWindow(requests int, window time.Duration, redisBased bool, origin []string) *RateLimiter {
	return &RateLimiter{
		Requests:   requests,
		Window:     window,
		ClientMap:  make(map[string]*Client),
		Origins:    origin,
		RedisBased: redisBased,
	}
}

// TokenRateLimiter stores tokenRate limit
type TokenRateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	mu         sync.Mutex
}

// ProxyResponseError represents the structure of the JSON error response
type ProxyResponseError struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JwtAuth  stores JWT configuration
type JwtAuth struct {
	AuthURL          string
	RequiredHeaders  []string
	Headers          map[string]string
	Params           map[string]string
	Origins          []string
	ErrorInterceptor errorinterceptor.ErrorInterceptor
}

// AuthenticationMiddleware Define struct
type AuthenticationMiddleware struct {
	AuthURL         string
	RequiredHeaders []string
	Headers         map[string]string
	Params          map[string]string
}
type AccessListMiddleware struct {
	Path             string
	Destination      string
	List             []string
	ErrorInterceptor errorinterceptor.ErrorInterceptor
}

// AuthBasic contains Basic auth configuration
type AuthBasic struct {
	Username         string
	Password         string
	Headers          map[string]string
	Params           map[string]string
	ErrorInterceptor errorinterceptor.ErrorInterceptor
}

// InterceptErrors contains backend status code errors to intercept
type InterceptErrors struct {
	Errors  []int
	Origins []string
}

// responseRecorder intercepts the response body and status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}
type Oauth struct {
	// ClientID is the application's ID.
	ClientID string
	// ClientSecret is the application's secret.
	ClientSecret string
	// Endpoint contains the resource server's token endpoint
	Endpoint OauthEndpoint
	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string
	// Scope specifies optional requested permissions.
	Scopes []string
	// contains filtered or unexported fields
	State            string
	Origins          []string
	JWTSecret        string
	Provider         string
	ErrorInterceptor errorinterceptor.ErrorInterceptor
}
type OauthEndpoint struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
}
