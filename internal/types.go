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

package pkg

import (
	"context"
	"github.com/gorilla/mux"
)

type Config struct {
	file string
}
type BasicRuleMiddleware struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Cors struct {
	// Cors Allowed origins,
	//e.g:
	//
	// - http://localhost:80
	//
	// - https://example.com
	Origins []string `yaml:"origins"`
	//
	//e.g:
	//
	//Access-Control-Allow-Origin: '*'
	//
	//    Access-Control-Allow-Methods: 'GET, POST, PUT, DELETE, OPTIONS'
	//
	//    Access-Control-Allow-Cors: 'Content-Type, Authorization'
	Headers map[string]string `yaml:"headers"`
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
	//e.g: Header X-Auth-UserId to query userId
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
	//CookiePath e.g: /my-protected-path or / || by default is applied on a route path
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
type RateLimiter struct {
	// ipBased, tokenBased
	Type string  `yaml:"type"`
	Rate float64 `yaml:"rate"`
	Rule int     `yaml:"rule"`
}

type AccessRuleMiddleware struct {
	ResponseCode int `yaml:"responseCode"` // HTTP Response code
}

// Middleware defined the route middleware
type Middleware struct {
	//Path contains the name of middleware and must be unique
	Name string `yaml:"name"`
	// Type contains authentication types
	//
	// basic, jwt, auth0, rateLimit, access
	Type  string   `yaml:"type"`  // Middleware type [basic, jwt, auth0, rateLimit, access]
	Paths []string `yaml:"paths"` // Protected paths
	// Rule contains rule type of
	Rule interface{} `yaml:"rule"` // Middleware rule
}
type MiddlewareName struct {
	name string `yaml:"name"`
}

// Route defines gateway route
type Route struct {
	// Name defines route name
	Name string `yaml:"name"`
	//Host Domain/host based request routing
	Host string `yaml:"host"`
	// Path defines route path
	Path string `yaml:"path"`
	// Rewrite rewrites route path to desired path
	//
	// E.g. /cart to / => It will rewrite /cart path to /
	Rewrite string `yaml:"rewrite"`
	// Destination Defines backend URL
	Destination string `yaml:"destination"`
	// Cors contains the route cors headers
	Cors Cors `yaml:"cors"`
	//RateLimit int      `yaml:"rateLimit"`
	// Methods allowed method
	Methods []string `yaml:"methods"`
	// DisableHeaderXForward Disable X-forwarded header.
	//
	// [X-Forwarded-Host, X-Forwarded-For, Host, Scheme ]
	//
	// It will not match the backend route
	DisableHeaderXForward bool `yaml:"disableHeaderXForward"`
	// HealthCheck Defines the backend is health check PATH
	HealthCheck string `yaml:"healthCheck"`
	// InterceptErrors intercepts backend errors based on the status codes
	//
	// Eg: [ 403, 405, 500 ]
	InterceptErrors []int `yaml:"interceptErrors"`
	// Middlewares Defines route middleware from Middleware names
	Middlewares []string `yaml:"middlewares"`
}

// Gateway contains Goma Proxy Gateway's configs
type Gateway struct {
	// SSLCertFile  SSL Certificate file
	SSLCertFile string `yaml:"sslCertFile" env:"GOMA_SSL_CERT_FILE, overwrite"`
	// SSLKeyFile SSL Private key  file
	SSLKeyFile string `yaml:"sslKeyFile" env:"GOMA_SSL_KEY_FILE, overwrite"`
	// WriteTimeout defines proxy write timeout
	WriteTimeout int `yaml:"writeTimeout" env:"GOMA_WRITE_TIMEOUT, overwrite"`
	// ReadTimeout defines proxy read timeout
	ReadTimeout int `yaml:"readTimeout" env:"GOMA_READ_TIMEOUT, overwrite"`
	// IdleTimeout defines proxy idle timeout
	IdleTimeout int `yaml:"idleTimeout" env:"GOMA_IDLE_TIMEOUT, overwrite"`
	// RateLimit Defines the number of request peer minutes
	RateLimit int `yaml:"rateLimit" env:"GOMA_RATE_LIMIT, overwrite"`
	// BlockCommonExploits enable, disable block common exploits
	BlockCommonExploits bool   `yaml:"blockCommonExploits"`
	AccessLog           string `yaml:"accessLog" env:"GOMA_ACCESS_LOG, overwrite"`
	ErrorLog            string `yaml:"errorLog" env:"GOMA_ERROR_LOG=, overwrite"`
	// DisableHealthCheckStatus enable and disable routes health check
	DisableHealthCheckStatus bool `yaml:"disableHealthCheckStatus"`
	// DisableRouteHealthCheckError allows enabling and disabling backend healthcheck errors
	DisableRouteHealthCheckError bool `yaml:"disableRouteHealthCheckError"`
	//Disable allows enabling and disabling displaying routes on start
	DisableDisplayRouteOnStart bool `yaml:"disableDisplayRouteOnStart"`
	// DisableKeepAlive allows enabling and disabling KeepALive server
	DisableKeepAlive bool `yaml:"disableKeepAlive"`
	// InterceptErrors holds the status codes to intercept the error from backend
	InterceptErrors []int `yaml:"interceptErrors"`
	// Cors holds proxy global cors
	Cors Cors `yaml:"cors"`
	// Routes holds proxy routes
	Routes []Route `yaml:"routes"`
}
type GatewayConfig struct {
	Version string `yaml:"version"`
	// GatewayConfig holds Gateway config
	GatewayConfig Gateway `yaml:"gateway"`
	// Middlewares holds proxy middlewares
	Middlewares []Middleware `yaml:"middlewares"`
}

// ErrorResponse represents the structure of the JSON error response
type ErrorResponse struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type GatewayServer struct {
	ctx         context.Context
	gateway     Gateway
	middlewares []Middleware
}
type ProxyRoute struct {
	path            string
	rewrite         string
	destination     string
	methods         []string
	cors            Cors
	disableXForward bool
}
type RoutePath struct {
	route       Route
	path        string
	rules       []string
	middlewares []Middleware
	router      *mux.Router
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
