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
	"github.com/jkaninda/goma-gateway/internal/middlewares"
)

// Route defines a gateway route configuration.
type Route struct {
	// Name provides a descriptive name for the route.
	Name string `yaml:"name"`
	// Path specifies the route's path.
	Path string `yaml:"path"`
	// Rewrite rewrites the incoming request path to a desired path.
	//
	// For example, `/cart` to `/` rewrites `/cart` to `/`.
	Rewrite string `yaml:"rewrite,omitempty"`
	// Priority, Determines route matching order
	Priority int `yaml:"priority,omitempty"`
	// Disabled specifies whether the route is disabled.
	// Deprecated, use Enabled
	Disabled bool `yaml:"disabled,omitempty"`
	// Enabled specifies whether the route is enabled.
	Enabled bool `yaml:"enabled,omitempty" default:"true"`
	// Hosts lists domains or hosts for request routing.
	Hosts []string `yaml:"hosts"`
	// Cors defines the route-specific Cross-Origin Resource Sharing (CORS) settings.
	Cors Cors `yaml:"cors,omitempty"`
	// Methods specifies the HTTP methods allowed for this route (e.g., GET, POST).
	Methods []string `yaml:"methods"`
	// Destination defines the primary backend URL for this route.
	// Deprecated, use Target
	Destination string `yaml:"destination,omitempty"`
	// Target defines the primary backend URL for this route.
	Target string `yaml:"target,omitempty"`
	// Backends specifies a list of backend URLs for load balancing.
	Backends Backends `yaml:"backends,omitempty"`
	// InsecureSkipVerify disables SSL/TLS verification for the backend.
	// Deprecated, use security
	InsecureSkipVerify bool `yaml:"insecureSkipVerify,omitempty"`
	// HealthCheck contains configuration for monitoring the health of backends.
	HealthCheck RouteHealthCheck `yaml:"healthCheck,omitempty"`
	// DisableHostForwarding disables the forwarding of host-related headers.
	//
	// The headers affected are:
	// - X-Forwarded-Host
	// - X-Forwarded-For
	// - Host
	// - Scheme
	//
	// If disabled, the backend may not match routes correctly.
	// Deprecated, use security.forwardHostHeaders
	DisableHostForwarding bool `yaml:"disableHostForwarding,omitempty"`
	// ErrorInterceptor provides configuration for handling backend errors.
	ErrorInterceptor middlewares.RouteErrorInterceptor `yaml:"errorInterceptor,omitempty"`
	// BlockCommonExploits
	// Deprecated
	BlockCommonExploits bool `yaml:"blockCommonExploits,omitempty"`
	// Maintenance puts the route in maintenance mode.
	// When enabled, requests to this route return the configured response
	// instead of being forwarded to the backend.
	Maintenance Maintenance `yaml:"maintenance,omitempty"`

	// TLS contains the TLS configuration for the route.
	TLS      TLS      `yaml:"tls,omitempty"`
	Security Security `yaml:"security,omitempty"`
	// DisableMetrics disables metrics collection for this route.
	DisableMetrics bool `yaml:"disableMetrics,omitempty"`
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
	Keys []TLSKey `yaml:"keys,omitempty"`
}

type TLSKey struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Backend defines backend server to route traffic to
type Backend struct {
	// unavailable defines backend server availability
	unavailable bool
	// Endpoint defines the endpoint of the backend
	Endpoint string `yaml:"endpoint,omitempty"`
	// Weight defines Weight for weighted algorithm, it optional
	Weight    int            `yaml:"weight,omitempty"`
	Match     []BackendMatch `yaml:"match,omitempty"`
	Exclusive bool           `yaml:"exclusive,omitempty"`
}

type Security struct {
	ForwardHostHeaders      bool        `yaml:"forwardHostHeaders" default:"true"`
	EnableExploitProtection bool        `yaml:"enableExploitProtection"`
	TLS                     SecurityTLS `yaml:"tls"`
}
type SecurityTLS struct {
	// Deprecated
	SkipVerification   bool   `yaml:"SkipVerification,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify,omitempty"`
	RootCAs            string `yaml:"rootCAs,omitempty"`
	ClientCert         string `yaml:"clientCert,omitempty"`
	ClientKey          string `yaml:"clientKey,omitempty"`
}

// Backends defines List of backend servers to route traffic to
type Backends []*Backend

func (r *Route) UnmarshalYAML(unmarshal func(interface{}) error) error {
	r.Enabled = true
	r.Security.ForwardHostHeaders = true
	r.Cors.Enabled = true
	type tmp Route
	return unmarshal((*tmp)(r))
}

// loadCertPool loads certificate pool with better error handling
func (r *Route) loadCertPool() (*x509.CertPool, error) {
	if len(r.Security.TLS.RootCAs) == 0 {
		return nil, nil
	}
	certPool, err := loadCertPool(r.Security.TLS.RootCAs)
	if err != nil {
		return nil, err
	}
	return certPool, nil
}
func (r *Route) loadClientCert() (*tls.Certificate, error) {
	if len(r.Security.TLS.ClientCert) == 0 || len(r.Security.TLS.ClientKey) == 0 {
		return nil, nil
	}
	clientCert, err := loadCertAndKey(r.Security.TLS.ClientCert, r.Security.TLS.ClientKey)
	if err != nil {
		return nil, err
	}
	return clientCert, nil
}

func (r *Route) initMTLS() (*tls.Certificate, *x509.CertPool, error) {
	var clientCert *tls.Certificate
	var certPool *x509.CertPool
	var err error
	// Check if mTLS is configured
	if len(r.Security.TLS.ClientCert) == 0 || len(r.Security.TLS.ClientKey) == 0 || len(r.Security.TLS.RootCAs) == 0 {
		return nil, nil, nil
	}
	// Load certificates
	certPool, err = r.loadCertPool()
	if err != nil {
		logger.Error("Failed to load rootCAs", "error", err)
		return nil, nil, err
	}
	clientCert, err = r.loadClientCert()
	if err != nil {
		logger.Error("Failed to load client certificate", "error", err)
		return nil, certPool, err
	}
	return clientCert, certPool, nil

}

type BackendMatch struct {
	Source   SourceType   `yaml:"source"`
	Name     string       `yaml:"name"`
	Operator OperatorType `yaml:"operator"`
	Value    string       `yaml:"value"`
}
type SourceType string
type OperatorType string
