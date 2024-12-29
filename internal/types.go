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
	"context"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"time"
)

type BasicRuleMiddleware struct {
	Realm    string   `yaml:"realm,omitempty"`
	Users    []string `yaml:"users"`
	Username string   `yaml:"username,omitempty"` // Deprecated, use Users
	Password string   `yaml:"password,omitempty"` // Deprecated, use Users
}
type ForwardAuthRuleMiddleware struct {
	URL                 string            `yaml:"url"`
	AuthResponseHeaders map[string]string `yaml:"authResponseHeaders"`
}
type AddPrefixRuleMiddleware struct {
	Prefix string `yaml:"prefix"`
}
type RedirectRegexRuleMiddleware struct {
	Pattern     string `yaml:"pattern"`
	Replacement string `yaml:"replacement"`
}

// JWTRuleMiddleware authentication using HTTP GET method
//
// JWTRuleMiddleware contains the authentication details
type JWTRuleMiddleware struct {
	// URL contains the authentication URL, it supports HTTP GET method only.
	URL string `yaml:"url"`
	// RequiredHeaders , contains required before sending request to the backend.
	RequiredHeaders []string `yaml:"requiredHeaders"`
	// Headers Add header to the backend from Authentication request's header, depending on your requirements.
	// Key is Http's response header Key, and value  is the backend Request's header Key.
	// In case you want to get headers from Authentication service and inject them to backend request's headers.
	Headers map[string]string `yaml:"headers"`
	// Params same as Headers, contains the request params.
	//
	// Gets authentication headers from authentication request and inject them as request params to the backend.
	//
	// Key is Http's response header Key, and value  is the backend Request's request param Key.
	//
	// In case you want to get headers from Authentication service and inject them to next request's params.
	//
	// e.g: Header X-Auth-UserId to query userId
	Params map[string]string `yaml:"params"`
}
type OauthRulerMiddleware struct {
	// ClientID is the application's ID.
	ClientID string `yaml:"clientId"`

	// ClientSecret is the application's secret.
	ClientSecret string `yaml:"clientSecret"`
	// oauth provider google, gitlab, github, amazon, facebook, custom
	Provider string `yaml:"provider"`
	// Endpoint contains the resource server's token endpoint
	Endpoint OauthEndpoint `yaml:"endpoint"`

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string `yaml:"redirectUrl"`
	// RedirectPath is the PATH to redirect users after authentication, e.g: /my-protected-path/dashboard
	RedirectPath string `yaml:"redirectPath"`
	// CookiePath e.g: /my-protected-path or / || by default is applied on a route path
	CookiePath string `yaml:"cookiePath"`

	// Scope specifies optional requested permissions.
	Scopes []string `yaml:"scopes"`
	// contains filtered or unexported fields
	State     string `yaml:"state"`
	JWTSecret string `yaml:"jwtSecret"`
}
type OauthEndpoint struct {
	AuthURL     string `yaml:"authUrl"`
	TokenURL    string `yaml:"tokenUrl"`
	UserInfoURL string `yaml:"userInfoUrl"`
}

type RateLimitRuleMiddleware struct {
	Unit            string `yaml:"unit"`
	RequestsPerUnit int    `yaml:"requestsPerUnit"`
}
type AccessRuleMiddleware struct {
	ResponseCode int `yaml:"responseCode"` // HTTP Response code
}

type RouteHealthCheck struct {
	Path            string `yaml:"path"`
	Interval        string `yaml:"interval"`
	Timeout         string `yaml:"timeout"`
	HealthyStatuses []int  `yaml:"healthyStatuses"`
}
type GatewayConfig struct {
	Version string `yaml:"version"`
	// GatewayConfig holds Gateway config
	GatewayConfig Gateway `yaml:"gateway"`
	// Middlewares holds proxy middlewares
	Middlewares []Middleware `yaml:"middlewares"`
}

type GatewayServer struct {
	ctx         context.Context
	configFile  string
	version     string
	gateway     Gateway
	middlewares []Middleware
}
type ProxyRoute struct {
	path                  string
	rewrite               string
	destination           string
	backends              []string
	methods               []string
	cors                  Cors
	disableHostForwarding bool
	insecureSkipVerify    bool
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
}
type Redis struct {
	// Addr redis hostname and port number :
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
}

// ExtraRouteConfig contains additional routes and middlewares directory
type ExtraRouteConfig struct {
	Directory string `yaml:"directory"`
	Watch     bool   `yaml:"watch"`
}

// AccessPolicyRuleMiddleware access policy
type AccessPolicyRuleMiddleware struct {
	Action       string   `yaml:"action,omitempty"` // action, ALLOW or DENY
	SourceRanges []string `yaml:"sourceRanges"`     //  list of Ips
}
type ProxyHandlerErrorInterceptor struct {
	Enabled     bool
	ContentType string
	Errors      []middlewares.RouteError
	Origins     []string
}
