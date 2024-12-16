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
	"bytes"
	"net/http"
	"sync"
	"time"
)

// RateLimiter defines requests limit properties.
type RateLimiter struct {
	requests   int
	unit       string
	id         string
	clientMap  map[string]*Client
	mu         sync.Mutex
	origins    []string
	redisBased bool
	pathBased  bool
	paths      []string
}

// Client stores request count and window expiration for each client.
type Client struct {
	RequestCount int
	ExpiresAt    time.Time
}
type RateLimit struct {
	Id         string
	Unit       string
	Requests   int
	Origins    []string
	Hosts      []string
	RedisBased bool
	PathBased  bool
	Paths      []string
}

// NewRateLimiterWindow creates a new RateLimiter.
func (rateLimit RateLimit) NewRateLimiterWindow() *RateLimiter {
	return &RateLimiter{
		id:         rateLimit.Id,
		unit:       rateLimit.Unit,
		requests:   rateLimit.Requests,
		clientMap:  make(map[string]*Client),
		origins:    rateLimit.Origins,
		redisBased: rateLimit.RedisBased,
		pathBased:  rateLimit.PathBased,
		paths:      rateLimit.Paths,
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
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

// JwtAuth  stores JWT configuration
type JwtAuth struct {
	Path            string
	Paths           []string
	AuthURL         string
	RequiredHeaders []string
	Headers         map[string]string
	Params          map[string]string
	Origins         []string
}

// AuthenticationMiddleware Define struct
type AuthenticationMiddleware struct {
	AuthURL         string
	RequiredHeaders []string
	Headers         map[string]string
	Params          map[string]string
}
type AccessListMiddleware struct {
	Path        string
	Destination string
	List        []string
	Origins     []string
}

// AuthBasic contains Basic auth configuration
type AuthBasic struct {
	// Route path
	Path     string
	Paths    []string
	Username string
	Password string
	Headers  map[string]string
	Params   map[string]string
}

// InterceptErrors contains backend status code errors to intercept
type InterceptErrors struct {
	Interceptor RouteErrorInterceptor
	Origins     []string
}

// responseRecorder intercepts the response body and status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}
type Oauth struct {
	// Route path
	Path string
	// Route protected path
	Paths []string
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
	State     string
	Origins   []string
	JWTSecret string
	Provider  string
}
type OauthEndpoint struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
}

type RouteErrorInterceptor struct {
	Enabled     bool         `yaml:"enabled"`
	ContentType string       `yaml:"contentType,omitempty"`
	Errors      []RouteError `yaml:"errors"`
}
type RouteError struct {
	Code int    `yaml:"code"`
	Body string `yaml:"body,omitempty"`
}
