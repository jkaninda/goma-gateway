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

// Route defines gateway route
type Route struct {
	// Path defines route path
	Path string `yaml:"path"`
	// Name defines route name
	Name string `yaml:"name"`
	// Host Domain/host based request routing
	// Host  string   `yaml:"host"`
	// Hosts Domains/hosts based request routing
	Hosts []string `yaml:"hosts"`
	// Rewrite rewrites route path to desired path
	//
	// E.g. /cart to / => It will rewrite /cart path to /
	Rewrite string `yaml:"rewrite"`
	//
	// Methods allowed method
	Methods []string `yaml:"methods"`
	// Destination Defines backend URL
	Destination        string   `yaml:"destination"`
	Backends           []string `yaml:"backends"`
	InsecureSkipVerify bool     `yaml:"insecureSkipVerify"`
	// HealthCheck Defines the backend is health
	HealthCheck RouteHealthCheck `yaml:"healthCheck"`
	// Cors contains the route cors headers
	Cors      Cors `yaml:"cors"`
	RateLimit int  `yaml:"rateLimit,omitempty"`
	// DisableHostForwarding Disable X-forwarded header.
	//
	// [X-Forwarded-Host, X-Forwarded-For, Host, Scheme ]
	//
	// It will not match the backend route
	DisableHostForwarding bool `yaml:"disableHostForwarding"`
	DisableHostFording    bool `yaml:"disableHostFording,omitempty"` // Deprecated, renamed to disableHostForwarding
	// InterceptErrors holds the status codes to intercept the error from backend
	InterceptErrors []int `yaml:"interceptErrors,omitempty"`
	// BlockCommonExploits enable, disable block common exploits
	BlockCommonExploits bool `yaml:"blockCommonExploits,omitempty"`
	// Middlewares Defines route middlewares from Middleware names
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
