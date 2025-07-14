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
	"github.com/jkaninda/goma-gateway/internal/middlewares"
)

// Gateway contains the configuration options for the Goma Proxy Gateway.
type Gateway struct {
	// TLS specifies a list of tls certificate, cert and key
	TLS TLS `yaml:"tls,omitempty"`
	// Redis contains the configuration details for the Redis database.
	Redis Redis `yaml:"redis,omitempty"`
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
	// Monitoring grouped monitoring and diagnostics configuration
	Monitoring Monitoring `yaml:"monitoring,omitempty"`
	// Log defines the logging config
	Log        Log        `yaml:"log"`
	Networking Networking `yaml:"networking,omitempty"`
	// When enabled, the router will match the path with or without a trailing slash.
	EnableStrictSlash bool `yaml:"enableStrictSlash,omitempty"`
	// EnableMetrics enables or disables server metrics collection.
	// Deprecated
	EnableMetrics bool `yaml:"enableMetrics,omitempty"`
	// ErrorInterceptor provides advanced error-handling configuration for intercepted backend errors.
	ErrorInterceptor middlewares.RouteErrorInterceptor `yaml:"errorInterceptor,omitempty"`
	// Cors defines the global Cross-Origin Resource Sharing (CORS) configuration for the gateway.
	Cors Cors `yaml:"cors,omitempty"`
	// ExtraConfig provides additional configuration, including routes and middleware, from a specified directory.
	ExtraConfig ExtraRouteConfig `yaml:"extraConfig,omitempty"`
	// Routes defines the list of proxy routes.
	Routes []Route `yaml:"routes"`
}
type EntryPoint struct {
	Web         EntryPointAddress `yaml:"web,omitempty"`
	WebSecure   EntryPointAddress `yaml:"webSecure,omitempty"`
	PassThrough EntryPointAddress `yaml:"passThrough,omitempty"`
}
type EntryPointAddress struct {
	Address  string        `yaml:"address,omitempty"`
	Forwards []ForwardRule `yaml:"forwards,omitempty"`
}

func (p EntryPoint) Validate() {
	// Validate web entry point
	if addr := p.Web.Address; addr != "" {
		if validateEntrypoint(addr) {
			webAddress = addr
		} else {
			logger.Warn("Invalid web address", "address", addr)
		}
	}

	// Validate webSecure entry point
	if addr := p.WebSecure.Address; addr != "" {
		if validateEntrypoint(addr) {
			webSecureAddress = addr
		} else {
			logger.Warn("Invalid webSecure address", "address", addr)
		}
	}

	// Validate passthrough forwards
	for _, forward := range p.PassThrough.Forwards {
		if !isPortValid(forward.Port) {
			logger.Fatal("Invalid forward port", "port", forward.Port)
		}

		switch forward.Protocol {
		case ProtocolTCP:
			logger.Debug("Protocol: TCP", "port", forward.Port, "target", forward.Target)
		case ProtocolUDP:
			logger.Debug("Protocol: UDP", "port", forward.Port, "target", forward.Target)
		case ProtocolTCPUDP:
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
	Format string `yaml:"format,omitempty" env:"GOMA_LOG_FORMAT, overwrite"`
}

// Monitoring defines the observability and health-related configuration.
type Monitoring struct {
	// EnableMetrics enables or disables server metrics collection.
	EnableMetrics bool `yaml:"enableMetrics,omitempty"`
	// Paths sets metrics custom path (default /metrics)
	Path string `yaml:"path,omitempty"`
	// Middleware name to apply to this Route
	Middleware  string      `yaml:"middleware,omitempty"`
	HealthCheck HealthCheck `yaml:"healthCheck,omitempty"`
}
type HealthCheck struct {
	EnableHealthCheckStatus     bool `yaml:"enableHealthCheckStatus,omitempty"`
	EnableRouteHealthCheckError bool `yaml:"enableRouteHealthCheckError,omitempty"`
}
type Protocol string
type ForwardRule struct {
	Protocol Protocol `yaml:"protocol,omitempty"`
	Port     int      `yaml:"port,omitempty"`
	Target   string   `yaml:"target,omitempty"`
}
type Timeouts struct {
	Write int `yaml:"write" env:"GOMA_WRITE_TIMEOUT,overwrite"`
	Read  int `yaml:"read" env:"GOMA_READ_TIMEOUT,overwrite"`
	Idle  int `yaml:"idle" env:"GOMA_IDLE_TIMEOUT,overwrite"`
}

type Networking struct {
	DNSCache      DNSCacheConfig `yaml:"dnsCache,omitempty"`
	ProxySettings ProxyConfig    `yaml:"proxy,omitempty"`
}
type DNSCacheConfig struct {
	Enable        bool     `yaml:"enable,omitempty"`
	TTL           int      `yaml:"ttl,omitempty"` // in seconds
	ClearOnReload bool     `yaml:"clearOnReload,omitempty"`
	Resolver      []string `yaml:"resolver,omitempty"` // e.g., ["8.8.8.8:53"]
}
type ProxyConfig struct {
	DisableCompression    bool `yaml:"disableCompression"`
	MaxIdleConns          int  `yaml:"maxIdleConns"`
	MaxIdleConnsPerHost   int  `yaml:"maxIdleConnsPerHost"`
	MaxConnsPerHost       int  `yaml:"maxConnsPerHost"`
	TLSHandshakeTimeout   int  `yaml:"tlsHandshakeTimeout"`
	ResponseHeaderTimeout int  `yaml:"responseHeaderTimeout"`
	IdleConnTimeout       int  `yaml:"idleConnTimeout"`
	ForceAttemptHTTP2     bool `yaml:"forceAttemptHTTP2"`
}

func (g *Gateway) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Proxy
	g.Networking.ProxySettings.ForceAttemptHTTP2 = true
	g.Networking.ProxySettings.MaxIdleConns = 512
	g.Networking.ProxySettings.MaxIdleConnsPerHost = 256
	g.Networking.ProxySettings.MaxConnsPerHost = 256
	g.Networking.ProxySettings.IdleConnTimeout = 90

	type tmp Gateway
	return unmarshal((*tmp)(g))
}
