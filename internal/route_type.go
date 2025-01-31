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

import "github.com/jkaninda/goma-gateway/internal/middlewares"

// Route defines a gateway route configuration.
type Route struct {
	// Path specifies the route's path.
	Path string `yaml:"path"`
	// Rewrite rewrites the incoming request path to a desired path.
	//
	// For example, `/cart` to `/` rewrites `/cart` to `/`.
	// Name provides a descriptive name for the route.
	Name string `yaml:"name"`
	// Priority, Determines route matching order
	Priority int `yaml:"priority,omitempty"`
	// Disabled specifies whether the route is disabled.
	Disabled bool `yaml:"disabled"`
	// Hosts lists domains or hosts for request routing.
	Hosts []string `yaml:"hosts"`
	// Cors defines the route-specific Cross-Origin Resource Sharing (CORS) settings.
	Cors    Cors   `yaml:"cors,omitempty"`
	Rewrite string `yaml:"rewrite,omitempty"`
	// Methods specifies the HTTP methods allowed for this route (e.g., GET, POST).
	Methods []string `yaml:"methods"`
	// Destination defines the primary backend URL for this route.
	Destination string `yaml:"destination,omitempty"` // Deprecated, use Backends
	// Backends specifies a list of backend URLs for load balancing.
	Backends Backends `yaml:"backends"`
	// InsecureSkipVerify disables SSL/TLS verification for the backend.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// HealthCheck contains configuration for monitoring the health of backends.
	HealthCheck RouteHealthCheck `yaml:"healthCheck,omitempty"`
	// RateLimit specifies the maximum number of requests allowed per minute for this route.
	RateLimit int `yaml:"rateLimit,omitempty"` // Deprecated
	// DisableHostForwarding disables the forwarding of host-related headers.
	//
	// The headers affected are:
	// - X-Forwarded-Host
	// - X-Forwarded-For
	// - Host
	// - Scheme
	//
	// If disabled, the backend may not match routes correctly.
	DisableHostForwarding bool `yaml:"disableHostForwarding"`
	// DisableHostFording is deprecated and replaced by DisableHostForwarding.
	DisableHostFording bool `yaml:"disableHostFording,omitempty"` // Deprecated
	// InterceptErrors contains HTTP status codes for intercepting backend errors.
	// Deprecated: Use ErrorInterceptor for more advanced error handling.
	InterceptErrors []int `yaml:"interceptErrors,omitempty"`
	// ErrorInterceptor provides configuration for handling backend errors.
	ErrorInterceptor middlewares.RouteErrorInterceptor `yaml:"errorInterceptor,omitempty"`
	// BlockCommonExploits enables or disables blocking of common exploit patterns
	// such as SQL injection or simple XSS attempts.
	BlockCommonExploits bool `yaml:"blockCommonExploits,omitempty"`
	EnableBotDetection  bool `yaml:"enableBotDetection,omitempty"`
	TLS                 TLS  `yaml:"tls,omitempty"`
	// Middlewares lists middleware names to apply to this route.
	Middlewares []string `yaml:"middlewares"`
}

type ExtraRoute struct {
	// Routes holds proxy routes
	Routes []Route `yaml:"routes"`
}
type ExtraMiddleware struct {
	// Routes holds proxy routes
	Middlewares []Middleware `yaml:"middlewares"`
}
type TLS struct {
	Keys []struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"keys,omitempty"`
}

// Backend defines backend server to route traffic to
type Backend struct {
	// unavailable defines backend server availability
	unavailable bool
	// Endpoint defines the endpoint of the backend
	Endpoint string `yaml:"endpoint,omitempty"`
	// EndPointD
	// Deprecated, use Endpoint,  replaced by endpoint in YAML
	EndPointD string `yaml:"endPoint,omitempty"`
	// Weight defines Weight for weighted algorithm, it optional
	Weight int `yaml:"weight,omitempty"`
}

// Backends defines List of backend servers to route traffic to
type Backends []Backend
