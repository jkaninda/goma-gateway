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
	"crypto/rsa"
	"fmt"
	"golang.org/x/time/rate"
	"sync"
	"time"
)

// Client stores request count and window expiration for each client.
type Client struct {
	RequestCount int
	ExpiresAt    time.Time
	Tokens       float64
	LastRefill   time.Time
}
type RateLimit struct {
	Id          string
	Unit        string
	Path        string
	Requests    int
	Burst       int
	Origins     []string
	Hosts       []string
	RedisBased  bool
	PathBased   bool
	Paths       []string
	BanAfter    int
	BanDuration time.Duration
	KeyStrategy RateLimitKeyStrategy
}

// NewRateLimiterWindow creates a new RateLimiter.
func (rateLimit RateLimit) NewRateLimiterWindow() *RateLimiter {
	return &RateLimiter{
		id:          rateLimit.Id,
		unit:        rateLimit.Unit,
		requests:    rateLimit.Requests,
		burst:       rateLimit.Burst,
		clientMap:   make(map[string]*Client),
		origins:     rateLimit.Origins,
		redisBased:  rateLimit.RedisBased,
		pathBased:   rateLimit.PathBased,
		paths:       rateLimit.Paths,
		banList:     make(map[string]time.Time),
		banAfter:    rateLimit.BanAfter,
		banDuration: rateLimit.BanDuration,
		strikeMap:   make(map[string]int),
		redis:       RedisClient,
		keyStrategy: rateLimit.KeyStrategy,
		ctx:         context.Background(),
		path:        rateLimit.Path,
	}
}

// ProxyResponseError represents the structure of the JSON error response
type ProxyResponseError struct {
	Success    bool   `json:"success"`
	StatusCode int    `json:"statusCode"`
	Error      string `json:"error"`
}

// JwtAuth  stores JWT configuration
type JwtAuth struct {
	Path                 string
	Paths                []string
	Origins              []string
	Algo                 string
	Issuer               string
	Audience             string
	Secret               string
	JwksFile             *Jwks
	JwksUrl              string
	RsaKey               *rsa.PublicKey
	ClaimsExpression     string
	ForwardHeaders       map[string]string
	ForwardAuthorization bool
	parsedExpression     Expression
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
	Paths       []string
	Origins     []string
	StatusCode  int
}

// AuthBasic contains Basic auth configuration
type AuthBasic struct {
	Path            string
	Paths           []string
	Realm           string
	Users           []User
	ForwardUsername bool
	Ldap            *LDAP
	ConnPoolSize    int
	ConnPoolBurst   int
	ConnPoolTTL     string
	rateLimiter     *rate.Limiter
	rateLimitMu     sync.RWMutex
	rateLimitTTL    time.Duration
	rateLimitInit   sync.Once
}
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// InterceptErrors contains backend status code errors to intercept
type InterceptErrors struct {
	Interceptor RouteErrorInterceptor
	Origins     []string
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
	State      string
	Origins    []string
	CookiePath string
	Provider   string
}
type OauthEndpoint struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	JwksURL     string
}

type RouteErrorInterceptor struct {
	Enabled     bool         `yaml:"enabled"`
	ContentType string       `yaml:"contentType,omitempty"`
	Errors      []RouteError `yaml:"errors"`
}
type RouteError struct {
	Code       int    `yaml:"code,omitempty"`   // Deprecated
	Status     int    `yaml:"status,omitempty"` // Deprecated
	StatusCode int    `yaml:"statusCode,omitempty"`
	Body       string `yaml:"body,omitempty"`
	File       string `yaml:"file,omitempty"`
}

type ForwardAuth struct {
	Path                        string
	Paths                       []string
	InsecureSkipVerify          bool
	AuthRequestHeaders          []string
	AddAuthCookiesToResponse    []string
	AuthResponseHeaders         []string
	AuthResponseHeadersAsParams []string
	AuthURL                     string
	AuthSignIn                  string
	ForwardHostHeaders          bool
	Origins                     []string
}
type ClaimExpression interface {
	Evaluate(claims map[string]interface{}) (bool, error)
}

func (r RouteErrorInterceptor) Validate() error {
	if len(r.Errors) == 0 {
		return fmt.Errorf("empty errors in error interceptor middleware")
	}
	return nil
}
