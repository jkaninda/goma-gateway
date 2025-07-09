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
	WriteTimeout int `yaml:"writeTimeout" env:"GOMA_WRITE_TIMEOUT, overwrite"`
	// ReadTimeout defines the timeout (in seconds) for reading requests from clients.
	ReadTimeout int `yaml:"readTimeout" env:"GOMA_READ_TIMEOUT, overwrite"`
	// IdleTimeout defines the timeout (in seconds) for idle connections.
	IdleTimeout int        `yaml:"idleTimeout" env:"GOMA_IDLE_TIMEOUT, overwrite"`
	EntryPoints EntryPoint `yaml:"entryPoints,omitempty"`
	// Grouped monitoring and diagnostics configuration
	Monitoring Monitoring `yaml:"monitoring,omitempty"`
	// EnableExploitProtection enables or disables blocking of common exploit patterns.
	EnableExploitProtection bool `yaml:"enableExploitProtection,omitempty"`
	// BlockCommonExploits
	// Deprecated, use EnableExploitProtection
	BlockCommonExploits bool `yaml:"blockCommonExploits,omitempty"`
	// Log defines the logging config
	Log Log `yaml:"log"`
	// DisableHealthCheckStatus enables or disables health checks for routes.
	DisableHealthCheckStatus bool `yaml:"disableHealthCheckStatus,omitempty"`
	// DisableRouteHealthCheckError enables or disables logging of backend health check errors.
	DisableRouteHealthCheckError bool `yaml:"disableRouteHealthCheckError,omitempty"`
	// DisableDisplayRouteOnStart enables or disables the display of routes during server startup.
	DisableDisplayRouteOnStart bool `yaml:"disableDisplayRouteOnStart,omitempty"`
	// EnableStrictSlash enables or disables strict routing and trailing slashes.
	//
	// When enabled, the router will match the path with or without a trailing slash.
	EnableStrictSlash bool `yaml:"enableStrictSlash,omitempty"`
	// EnableMetrics enables or disables server metrics collection.
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
}
type Protocol string
type ForwardRule struct {
	Protocol Protocol `yaml:"protocol,omitempty"`
	Port     int      `yaml:"port,omitempty"`
	Target   string   `yaml:"target,omitempty"`
}
