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
	Path string `yaml:"path" json:"path"`
	// Name provides a descriptive name for the route.
	Name string `yaml:"name" json:"name"`
	// Disabled specifies whether the route is disabled.
	Disabled bool `yaml:"disabled" json:"disabled"`
	// Hosts lists domains or hosts for request routing.
	Hosts []string `yaml:"hosts" json:"hosts"`
	// Cors defines the route-specific Cross-Origin Resource Sharing (CORS) settings.
	Cors Cors `yaml:"cors,omitempty" json:"cors"`
	// Rewrite rewrites the incoming request path to a desired path.
	//
	// For example: `/cart` to `/` rewrites `/cart` to `/`.
	Rewrite string `yaml:"rewrite,omitempty" json:"rewrite"`
	// Methods specifies the HTTP methods allowed for this route (e.g., GET, POST).
	Methods []string `yaml:"methods" json:"methods"`
	// Destination defines the primary backend URL for this route.
	Destination string `yaml:"destination" json:"destination"`
	// Backends specifies a list of backend URLs for load balancing.
	Backends []string `yaml:"backends" json:"backends"`
	// InsecureSkipVerify disables SSL/TLS verification for the backend.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify" json:"insecureSkipVerify"`
	// HealthCheck contains configuration for monitoring the health of backends.
	HealthCheck RouteHealthCheck `yaml:"healthCheck,omitempty" json:"healthCheck"`
	// RateLimit specifies the maximum number of requests allowed per minute for this route.
	RateLimit int `yaml:"rateLimit,omitempty" json:"rateLimit,omitempty"` // Deprecated
	// DisableHostForwarding disables the forwarding of host-related headers.
	//
	// The headers affected are:
	// - X-Forwarded-Host
	// - X-Forwarded-For
	// - Host
	// - Scheme
	//
	// If disabled, the backend may not match routeHandler correctly.
	DisableHostForwarding bool `yaml:"disableHostForwarding" json:"disableHostForwarding"`
	// DisableHostFording is deprecated and replaced by DisableHostForwarding.
	DisableHostFording bool `yaml:"disableHostFording,omitempty" json:"disableHostFording,omitempty"` // Deprecated
	// InterceptErrors contains HTTP status codes for intercepting backend errors.
	// Deprecated: Use ErrorInterceptor for more advanced error handling.
	InterceptErrors []int `yaml:"interceptErrors,omitempty" json:"interceptErrors,omitempty"`
	// ErrorInterceptor provides configuration for handling backend errors.
	ErrorInterceptor middlewares.RouteErrorInterceptor `yaml:"errorInterceptor,omitempty" json:"errorInterceptor"`
	// BlockCommonExploits enables or disables blocking of common exploit patterns
	// such as SQL injection or simple XSS attempts.
	BlockCommonExploits bool `yaml:"blockCommonExploits,omitempty" json:"blockCommonExploits"`
	EnableBotDetection  bool `yaml:"enableBotDetection,omitempty" json:"enableBotDetection"`
	// Middlewares lists middleware names to apply to this route.
	Middlewares []string `yaml:"middlewares" json:"middlewares"`
}

type ExtraRoute struct {
	// Routes holds proxy routes
	Routes []Route `yaml:"routes"`
}
type ExtraMiddleware struct {
	// Routes holds proxy routeHandler
	Middlewares []Middleware `yaml:"middlewares"`
}
