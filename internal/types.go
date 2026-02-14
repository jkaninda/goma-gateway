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

package internal

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/pkg/certmanager"
	"strings"
	"time"
)

type TlsCertificates struct {
	// CertsDir loads multiple certificates from a single directory
	CertsDir     string `yaml:"certsDir" json:"certsDir,omitempty"`
	Certificates []TLS  `yaml:"certificates,omitempty" json:"certificates,omitempty"`
	// Keys
	// Deprecated: use Certificates or CertsDir instead
	Keys       []TLS         `yaml:"keys,omitempty" json:"keys,omitempty"`
	ClientAuth TLSClientAuth `yaml:"clientAuth,omitempty" json:"clientAuth,omitempty"`
	Default    TLS           `yaml:"default,omitempty" json:"default,omitempty"`
}

type TLS struct {
	Cert string `yaml:"cert,omitempty" json:"cert,omitempty"`
	Key  string `yaml:"key,omitempty" json:"key,omitempty"`
}
type TLSClientAuth struct {
	ClientCA string `yaml:"clientCA,omitempty" json:"clientCA,omitempty"`
	Required bool   `yaml:"required,omitempty" json:"required,omitempty"`
}
type BasicRuleMiddleware struct {
	Realm           string `yaml:"realm,omitempty" json:"realm"`
	ForwardUsername bool   `yaml:"forwardUsername" json:"forwardUsername"`
	Users           Users  `yaml:"users" json:"users"`
}
type Users []middlewares.User

func (u *Users) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Try to unmarshal as []User first (new format)
	var userList []middlewares.User
	if err := unmarshal(&userList); err == nil {
		*u = userList
		return nil
	}

	// Fallback: try to unmarshal as []string (old format)
	var strList []string
	if err := unmarshal(&strList); err != nil {
		return err
	}

	// Convert []string to []User
	*u = make(Users, 0, len(strList))
	for _, entry := range strList {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid user format: %q, expected username:password", entry)
		}
		*u = append(*u, middlewares.User{
			Username: parts[0],
			Password: parts[1],
		})
	}
	return nil
}

type LdapRuleMiddleware struct {
	Realm           string `yaml:"realm,omitempty" json:"realm"`
	ForwardUsername bool   `yaml:"forwardUsername" json:"forwardUsername"`
	ConnPool        struct {
		Size  int    `yaml:"size" json:"size"`
		Burst int    `yaml:"burst" json:"burst"`
		TTL   string `yaml:"ttl" json:"ttl"`
	} `yaml:"connPool,omitempty"`
	URL                string `yaml:"url" json:"url"`
	BaseDN             string `yaml:"baseDN" json:"baseDN"`
	BindDN             string `yaml:"bindDN" json:"bindDN"`
	BindPass           string `yaml:"bindPass" json:"bindPass"`
	UserFilter         string `yaml:"userFilter" json:"userFilter"`
	StartTLS           bool   `yaml:"startTLS" json:"startTLS"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify" json:"insecureSkipVerify"`
}
type ForwardAuthRuleMiddleware struct {
	AuthURL    string `yaml:"authUrl" json:"authUrl"`
	AuthSignIn string `yaml:"authSignIn,omitempty" json:"authSignIn"`
	// Deprecated: Use ForwardHostHeaders instead
	EnableHostForwarding bool `yaml:"enableHostForwarding,omitempty"`
	ForwardHostHeaders   bool `yaml:"forwardHostHeaders,omitempty" json:"forwardHostHeaders"`
	// Deprecated: Use SkipInsecureVerify instead
	SkipInsecureVerify          bool     `yaml:"skipInsecureVerify,omitempty"`
	InsecureSkipVerify          bool     `yaml:"insecureSkipVerify,omitempty" json:"insecureSkipVerify"`
	AuthRequestHeaders          []string `yaml:"authRequestHeaders,omitempty" json:"authRequestHeaders"`
	AddAuthCookiesToResponse    []string `yaml:"addAuthCookiesToResponse,omitempty" json:"addAuthCookiesToResponse"`
	AuthResponseHeaders         []string `yaml:"authResponseHeaders,omitempty" json:"authResponseHeaders"`
	AuthResponseHeadersAsParams []string `yaml:"authResponseHeadersAsParams,omitempty" json:"authResponseHeadersAsParams"`
}
type AddPrefixRuleMiddleware struct {
	Prefix string `yaml:"prefix" json:"prefix"`
}
type RewriteRegexRuleMiddleware struct {
	Pattern     string `yaml:"pattern" json:"pattern"`
	Replacement string `yaml:"replacement" json:"replacement"`
}

// JWTRuleMiddleware authentication using HTTP GET method
//
// JWTRuleMiddleware contains the authentication details
type JWTRuleMiddleware struct {
	Alg                  string            `yaml:"alg,omitempty" json:"alg"`
	Secret               string            `yaml:"secret,omitempty" json:"secret"`
	PublicKey            string            `yaml:"publicKey,omitempty" json:"publicKey"`
	Issuer               string            `yaml:"issuer,omitempty" json:"issuer"`
	Audience             string            `yaml:"audience,omitempty" json:"audience"`
	JwksUrl              string            `yaml:"jwksUrl,omitempty" json:"jwksUrl"`
	JwksFile             string            `yaml:"jwksFile,omitempty" json:"jwksFile"`
	ForwardAuthorization bool              `yaml:"forwardAuthorization,omitempty" json:"forwardAuthorization"`
	ClaimsExpression     string            `yaml:"claimsExpression,omitempty" json:"claimsExpression"`
	ForwardHeaders       map[string]string `yaml:"forwardHeaders,omitempty" json:"forwardHeaders"`
}
type OauthRulerMiddleware struct {
	// ClientID is the application's ID.
	ClientID string `yaml:"clientId" json:"clientId"`

	// ClientSecret is the application's secret.
	ClientSecret string `yaml:"clientSecret" json:"clientSecret"`
	// oauth provider google, gitlab, github, amazon, facebook, custom
	Provider string `yaml:"provider" json:"provider"`
	// Endpoint contains the resource server's token endpoint
	Endpoint OauthEndpoint `yaml:"endpoint" json:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `yaml:"redirectUrl" json:"redirectUrl"`
	// RedirectPath is the PATH to redirect users after authentication, e.g: /my-protected-path/dashboard
	RedirectPath string `yaml:"redirectPath" json:"redirectPath"`
	// CookiePath e.g: /my-protected-path or / || by default is applied on a route path
	CookiePath string `yaml:"cookiePath" json:"cookiePath"`

	// Scope specifies optional requested permissions.
	Scopes []string `yaml:"scopes" json:"scopes"`
	// contains filtered or unexported fields
	State string `yaml:"state" json:"state"`
}
type OauthEndpoint struct {
	AuthURL     string `yaml:"authUrl" json:"authUrl"`
	TokenURL    string `yaml:"tokenUrl" json:"tokenUrl"`
	UserInfoURL string `yaml:"userInfoUrl" json:"userInfoUrl"`
	JwksURL     string `yaml:"jwksUrl" json:"jwksUrl"`
}

type RateLimitRuleMiddleware struct {
	Unit            string                   `yaml:"unit" json:"unit"`
	RequestsPerUnit int                      `yaml:"requestsPerUnit" json:"requestsPerUnit"`
	Burst           int                      `yaml:"burst" json:"burst"`
	BanAfter        int                      `yaml:"banAfter,omitempty" json:"banAfter"`       // Ban IP after this many failed requests
	BanDuration     string                   `yaml:"banDuration,omitempty" json:"banDuration"` // Duration to ban IP
	KeyStrategy     RateLimitRuleKeyStrategy `yaml:"keyStrategy,omitempty" json:"keyStrategy"`
}
type RateLimitRuleKeyStrategy struct {
	Source string `yaml:"source" json:"source"` // "ip", "header", "cookie"
	Name   string `yaml:"name" json:"name"`     // header name or cookie name

}

func (r *RateLimitRuleMiddleware) UnmarshalYAML(unmarshal func(interface{}) error) error {
	r.BanDuration = "10m" // Default ban duration to 10 minutes
	type tmp RateLimitRuleMiddleware
	return unmarshal((*tmp)(r))
}

type AccessRuleMiddleware struct {
	StatusCode int `yaml:"statusCode,omitempty" json:"statusCode"` // HTTP Response code
}

type RouteHealthCheck struct {
	Path            string `yaml:"path" json:"path"`
	Interval        string `yaml:"interval" json:"interval"`
	Timeout         string `yaml:"timeout" json:"timeout"`
	HealthyStatuses []int  `yaml:"healthyStatuses" json:"healthyStatuses"`
}
type GatewayConfig struct {
	Version string `yaml:"version" `
	// Gateway holds Gateway config
	Gateway Gateway `yaml:"gateway"`
	// Middlewares holds proxy middlewares
	Middlewares []Middleware `yaml:"middlewares"`
	// CertificateManager holds acme configuration
	// Deprecated
	CertificateManager *certmanager.Config `yaml:"certificateManager,omitempty"`
	// CertManager hols CertManager config
	CertManager *certmanager.Config `yaml:"certManager"`
	// Plugins configuration
	Plugins PluginConfig `yaml:"plugins,omitempty"`
}

type DefaultConfig struct {
	Middlewares []string `yaml:"middlewares"`
}

type HealthCheckRoute struct {
	DisableRouteHealthCheckError bool
	Routes                       []Route
}

// HealthCheckResponse represents the health check response structure
type HealthCheckResponse struct {
	Status string                     `json:"status"`
	Routes []HealthCheckRouteResponse `json:"routes"`
}

// HealthCheckRouteResponse represents the health check response for a route
type HealthCheckRouteResponse struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error"`
}
type UserInfo struct {
	Email string `json:"email"`
}

type JWTSecret struct {
	ISS    string `yaml:"iss"`
	Secret string `yaml:"secret"`
}

// Health represents the health check content for a route
type Health struct {
	Name               string
	URL                string
	TimeOut            time.Duration
	Interval           string
	HealthyStatuses    []int
	InsecureSkipVerify bool
	certPool           *x509.CertPool
	clientCerts        []tls.Certificate
}

// ExtraRouteConfig contains additional routes and middlewares directory
type ExtraRouteConfig struct {
	Directory string `yaml:"directory"`
	Watch     bool   `yaml:"watch"`
}

// AccessPolicyRuleMiddleware access policy
type AccessPolicyRuleMiddleware struct {
	Action       string   `yaml:"action,omitempty" json:"action"`   // action, ALLOW or DENY
	SourceRanges []string `yaml:"sourceRanges" json:"sourceRanges"` //  list of Ips
}
type UserAgentBlockRuleMiddleware struct {
	UserAgents []string `yaml:"userAgents" json:"userAgents"`
}
type ProxyMiddleware struct {
	Name           string
	Path           string
	Enabled        bool
	ContentType    string
	Errors         []middlewares.RouteError
	Origins        []string
	VisitorTracker *VisitorTracker
	enableMetrics  bool
	logRule        *LogEnrichRule
	headers        []ResponseHeader
}
type httpCacheRule struct {
	MaxTtl                   int64    `yaml:"maxTtl" json:"maxTtl"`
	MaxStale                 int64    `yaml:"maxStale" json:"maxStale"`
	DisableCacheStatusHeader bool     `yaml:"disableCacheStatusHeader,omitempty" json:"disableCacheStatusHeader"`
	MemoryLimit              string   `yaml:"memoryLimit,omitempty" json:"memoryLimit"`
	CacheableStatusCodes     []int    `yaml:"cacheableStatusCodes,omitempty" json:"cacheableStatusCodes"`
	ExcludedResponseCodes    []string `yaml:"excludedResponseCodes,omitempty" json:"excludedResponseCodes"`
	IncludeQueryInKey        bool     `yaml:"includeQueryInKey,omitempty" json:"includeQueryInKey"`
	QueryParamsToCache       []string `yaml:"queryParamsToCache,omitempty" json:"queryParamsToCache"`
}
type RedirectSchemeRuleMiddleware struct {
	Scheme    string `yaml:"scheme" json:"scheme"`
	Port      int64  `yaml:"port" json:"port"`
	Permanent bool   `yaml:"permanent,omitempty" json:"permanent"`
}
type RedirectRuleMiddleware struct {
	Url       string `yaml:"url,omitempty" json:"url"`
	Permanent bool   `yaml:"permanent,omitempty" json:"permanent"`
}
type RedirectRegexRuleMiddleware struct {
	Pattern     string `yaml:"pattern" json:"pattern"`
	Replacement string `yaml:"replacement" json:"replacement"`
	Permanent   bool   `yaml:"permanent,omitempty" json:"permanent"`
}
type BodyLimitRuleMiddleware struct {
	Limit string `yaml:"limit" json:"limit"`
}
type contextKey string

type LogEnrichRule struct {
	Headers []string `yaml:"headers,omitempty" json:"headers"`
	Query   []string `yaml:"query,omitempty" json:"query"`
	Cookies []string `yaml:"cookies,omitempty" json:"cookies"`
}

// ResponseHeader defines the configuration structure for managing response headers
// including CORS and custom security headers
type ResponseHeader struct {
	// Name specifies the unique name of the header policy (inherited from middleware)
	Name string `yaml:"name,omitempty" json:"name"`

	// MatchedPath stores the path pattern that matched this policy (used for sorting by specificity)
	MatchedPath string   `yaml:"-"`
	Paths       []string `yaml:"paths" json:"paths"`

	// Cors contains CORS (Cross-Origin Resource Sharing) configuration
	// When enabled, CORS headers will be added/override backend CORS headers
	Cors *Cors `yaml:"cors,omitempty" json:"cors"`

	// SetHeaders contains headers to set or override in the response
	// Behavior:
	// - If the backend sends a header with the same key, it will be overridden
	// - If the backend doesn't send the header, it will be added
	// - Set value to empty string "" to remove a backend header
	//
	// Examples:
	//   X-Frame-Options: "DENY"              # Add or override
	//   X-Content-Type-Options: "nosniff"    # Add or override
	//   X-Powered-By: ""                     # Remove backend header
	//   Server: ""                           # Remove backend header
	SetHeaders map[string]string `yaml:"setHeaders,omitempty" json:"setHeaders"`
	// SetCookies contains cookies to set in the response
	SetCookies    []Cookie `yaml:"setCookies,omitempty" json:"setCookies"`
	CacheControl  string   `yaml:"cacheControl,omitempty" json:"cacheControl"`
	CacheStatuses []int    `yaml:"cacheStatuses,omitempty" json:"cacheStatuses"`
}

// RetryPolicy defines retry behavior for a route
type RetryPolicy struct {
	MaxAttempts int           `json:"maxAttempts" yaml:"maxAttempts"`
	Delay       time.Duration `json:"delay" yaml:"delay"`
	MaxDelay    time.Duration `json:"maxDelay,omitempty" yaml:"maxDelay,omitempty"`
	Backoff     string        `json:"backoff,omitempty" yaml:"backoff,omitempty"`
}
