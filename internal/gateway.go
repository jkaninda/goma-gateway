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
	"github.com/jkaninda/goma-gateway/internal/config"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/internal/proxy"
)

// Gateway contains the configuration options for the Goma Gateway.
type Gateway struct {
	// TLS specifies a list of tls certificate, cert and key
	TLS TlsCertificates `yaml:"tls,omitempty"`
	// Redis contains the configuration details for the Redis database.
	Redis middlewares.Redis `yaml:"redis,omitempty"`
	// WriteTimeout defines the timeout (in seconds) for writing responses to clients.
	// Deprecated
	WriteTimeout int `yaml:"writeTimeout,omitempty" env:"GOMA_WRITE_TIMEOUT, overwrite"`
	// ReadTimeout defines the timeout (in seconds) for reading requests from clients.
	// Deprecated
	ReadTimeout int `yaml:"readTimeout,omitempty" env:"GOMA_READ_TIMEOUT, overwrite"`
	// IdleTimeout defines the timeout (in seconds) for idle connections.
	// Deprecated
	IdleTimeout int `yaml:"idleTimeout,omitempty" env:"GOMA_IDLE_TIMEOUT, overwrite"`
	// Timeouts defines server timeout in second
	Timeouts Timeouts `yaml:"timeouts,omitempty"`
	// EntryPoints of the server
	EntryPoints EntryPoint `yaml:"entryPoints,omitempty"`
	// Providers defines the configuration for various providers.
	Providers Providers `yaml:"providers,omitempty"`

	// Proxy defines how Goma Gateway behaves when running behind a reverse proxy or CDN (e.g., Cloudflare, Nginx, HAProxy, AWS ELB, Traefik, etc.)
	Proxy config.ProxyConfig `yaml:"proxy,omitempty"`
	// Monitoring grouped monitoring and diagnostics configuration
	Monitoring Monitoring `yaml:"monitoring,omitempty"`
	// Log defines the logging config
	Log        Log        `yaml:"log"`
	Networking Networking `yaml:"networking,omitempty"`
	// When enabled, the router will match the path with or without a trailing slash.
	StrictSlash bool `yaml:"strictSlash,omitempty"`
	// EnableMetrics enables or disables server metrics collection.
	// Deprecated
	EnableMetrics bool `yaml:"enableMetrics,omitempty"`
	// Debug enables or disables debug mode for the gateway.
	Debug bool `yaml:"debug,omitempty"`
	// ErrorInterceptor provides advanced error-handling configuration for intercepted backend errors.
	// Deprecated, use errorInterceptor middleware type
	ErrorInterceptor middlewares.RouteErrorInterceptor `yaml:"errorInterceptor,omitempty"`
	// Cors defines the global Cross-Origin Resource Sharing (CORS) configuration for the gateway.
	// Deprecated, use responseHeaders middleware type
	Cors Cors `yaml:"cors,omitempty"`
	// ExtraConfig provides additional configuration, including routes and middleware, from a specified directory.
	ExtraConfig ExtraRouteConfig `yaml:"extraConfig,omitempty"`
	// Defaults holds default configurations applied to routes
	Defaults DefaultConfig `yaml:"defaults,omitempty"`
	// Routes defines the list of proxy routes.
	Routes []Route `yaml:"routes"`
}
type EntryPoint struct {
	Web         EntryPointAddress `yaml:"web,omitempty"`
	WebSecure   EntryPointAddress `yaml:"webSecure,omitempty"`
	PassThrough EntryPointAddress `yaml:"passThrough,omitempty"`
}
type EntryPointAddress struct {
	Address  string              `yaml:"address,omitempty"`
	Forwards []proxy.ForwardRule `yaml:"forwards,omitempty"`
}

func (p EntryPoint) Validate() {
	// Validate web entry point
	if addr := p.Web.Address; addr != "" {
		if validateEntrypoint(addr) {
			webAddress = addr
		} else {
			logger.Fatal("Error, invalid web address", "address", addr)
		}
	}

	// Validate webSecure entry point
	if addr := p.WebSecure.Address; addr != "" {
		if validateEntrypoint(addr) {
			webSecureAddress = addr
		} else {
			logger.Fatal("Error, invalid webSecure address", "address", addr)
		}
	}

	// Validate passthrough forwards
	for _, forward := range p.PassThrough.Forwards {
		if !isPortValid(forward.Port) {
			logger.Fatal("Invalid forward port", "port", forward.Port)
		}

		switch forward.Protocol {
		case proxy.ProtocolTCP:
			logger.Debug("Protocol: TCP", "port", forward.Port, "target", forward.Target)
		case proxy.ProtocolUDP:
			logger.Debug("Protocol: UDP", "port", forward.Port, "target", forward.Target)
		case proxy.ProtocolTCPUDP:
			logger.Debug("Protocol: TCP/UDP", "port", forward.Port, "target", forward.Target)
		default:
			logger.Fatal("Unknown protocol", "protocol", forward.Protocol, "port", forward.Port)
		}
	}
}

type Log struct {
	// Level defines the logging level (e.g., info, debug, trace, off).
	Level string `yaml:"level,omitempty"  env:"GOMA_LOG_LEVEL, overwrite"`
	// FilePath specifies the file path for logs, default Stdout.
	FilePath string `yaml:"filePath,omitempty" env:"GOMA_LOG_FILE, overwrite"`
	// Format defines the logging format (eg. text, json)
	Format     string `yaml:"format,omitempty" env:"GOMA_LOG_FORMAT, overwrite"`
	MaxAgeDays int    `yaml:"maxAgeDays,omitempty"`
	MaxBackups int    `yaml:"maxBackups,omitempty"`
	MaxSizeMB  int    `yaml:"maxSizeMB,omitempty"`
}

// Monitoring defines the observability and health-related configuration.
type Monitoring struct {
	// EnableMetrics enables or disables Prometheus metrics collection (default: false).
	EnableMetrics bool `yaml:"enableMetrics,omitempty"`
	// Host Restrict observability access to this hostname
	Host string `yaml:"host,omitempty"`
	// MetricsPath sets a custom path for metrics (default: /metrics).
	MetricsPath string `yaml:"metricsPath,omitempty"`

	// EnableReadiness controls exposure of the /readyz endpoint (default: true).
	EnableReadiness bool `yaml:"enableReadiness,omitempty"`

	// EnableLiveness controls exposure of the /healthz endpoint (default: true).
	EnableLiveness bool `yaml:"enableLiveness,omitempty"`

	// EnableRouteHealthCheck controls the /healthz/routes endpoint (default: false).
	EnableRouteHealthCheck bool `yaml:"enableRouteHealthCheck,omitempty"`

	// IncludeRouteHealthErrors determines whether route health errors are reported in /healthz/routes (default: false).
	IncludeRouteHealthErrors bool `yaml:"includeRouteHealthErrors,omitempty"`

	// Middleware assigns middleware to monitoring-related endpoints.
	Middleware MonitoringMiddleware `yaml:"middleware,omitempty"`
}

type MonitoringMiddleware struct {
	Metrics          []string `yaml:"metrics,omitempty"`          // specifically for /metrics
	RouteHealthCheck []string `yaml:"routeHealthCheck,omitempty"` // optional, for /healthz/routes`
}

type Timeouts struct {
	Write int `yaml:"write" env:"GOMA_WRITE_TIMEOUT,overwrite"`
	Read  int `yaml:"read" env:"GOMA_READ_TIMEOUT,overwrite"`
	Idle  int `yaml:"idle" env:"GOMA_IDLE_TIMEOUT,overwrite"`
}

type Networking struct {
	DNSCache  DNSCacheConfig  `yaml:"dnsCache,omitempty"`
	Transport TransportConfig `yaml:"transport,omitempty"`
}
type DNSCacheConfig struct {
	// TTL in seconds
	TTL           int  `yaml:"ttl,omitempty"`
	ClearOnReload bool `yaml:"clearOnReload,omitempty"`
	// Resolver
	Resolver []string `yaml:"resolver,omitempty"`
}
type TransportConfig struct {
	InsecureSkipVerify    bool `yaml:"insecureSkipVerify,omitempty"`
	DisableCompression    bool `yaml:"disableCompression,omitempty"`
	MaxIdleConns          int  `yaml:"maxIdleConns,omitempty"`
	MaxIdleConnsPerHost   int  `yaml:"maxIdleConnsPerHost,omitempty"`
	MaxConnsPerHost       int  `yaml:"maxConnsPerHost,omitempty"`
	TLSHandshakeTimeout   int  `yaml:"tlsHandshakeTimeout,omitempty"`
	ResponseHeaderTimeout int  `yaml:"responseHeaderTimeout,omitempty"`
	IdleConnTimeout       int  `yaml:"idleConnTimeout,omitempty"`
	ForceAttemptHTTP2     bool `yaml:"forceAttemptHTTP2,omitempty"`
}

func (g *Gateway) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Proxy
	g.Networking.Transport.ForceAttemptHTTP2 = true
	g.Networking.Transport.MaxIdleConns = 512
	g.Networking.Transport.MaxIdleConnsPerHost = 256
	g.Networking.Transport.MaxConnsPerHost = 256
	g.Networking.Transport.IdleConnTimeout = 90

	// Monitoring
	g.Monitoring.EnableLiveness = true
	g.Monitoring.EnableReadiness = true
	g.StrictSlash = true

	// Cors
	g.Cors.Enabled = true

	type tmp Gateway
	return unmarshal((*tmp)(g))
}
