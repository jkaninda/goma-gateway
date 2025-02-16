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

import "github.com/jkaninda/goma-gateway/pkg/middlewares"

// Gateway contains the configuration options for the Goma Proxy Gateway.
type Gateway struct {
	// SSLCertFile specifies the SSL certificate file.
	// Deprecated: Use TlsCertFile instead.
	SSLCertFile string `yaml:"sslCertFile,omitempty" env:"GOMA_SSL_CERT_FILE, overwrite"`
	// SSLKeyFile specifies the SSL private key file.
	// Deprecated: Use TlsKeyFile instead.
	SSLKeyFile string `yaml:"sslKeyFile,omitempty" env:"GOMA_SSL_KEY_FILE, overwrite"`
	// TlsCertFile specifies the TLS certificate file.
	// Deprecated: Use TLS instead.
	TlsCertFile string `yaml:"tlsCertFile,omitempty" env:"GOMA_TLS_CERT_FILE, overwrite"`
	// TlsKeyFile specifies the TLS private key file.
	// Deprecated: Use TLS instead.
	TlsKeyFile string `yaml:"tlsKeyFile,omitempty" env:"GOMA_TLS_KEY_FILE, overwrite"`
	// TLS specifies a list of tls certificate, cert and key
	TLS TLS `yaml:"tls,omitempty"`
	// Redis contains the configuration details for the Redis database.
	Redis Redis `yaml:"redis,omitempty"`
	// WriteTimeout defines the timeout (in seconds) for writing responses to clients.
	WriteTimeout int `yaml:"writeTimeout" env:"GOMA_WRITE_TIMEOUT, overwrite"`
	// ReadTimeout defines the timeout (in seconds) for reading requests from clients.
	ReadTimeout int `yaml:"readTimeout" env:"GOMA_READ_TIMEOUT, overwrite"`
	// IdleTimeout defines the timeout (in seconds) for idle connections.
	IdleTimeout int `yaml:"idleTimeout" env:"GOMA_IDLE_TIMEOUT, overwrite"`
	// RateLimit specifies the maximum number of requests allowed per minute.
	RateLimit int `yaml:"rateLimit,omitempty" env:"GOMA_RATE_LIMIT, overwrite"` // Deprecated: RateLimit middleware type
	// BlockCommonExploits enables or disables blocking of common exploit patterns.
	BlockCommonExploits bool `yaml:"blockCommonExploits,omitempty"`
	// LogLevel defines the logging level (e.g., info, debug, trace, off).
	LogLevel string `yaml:"logLevel" env:"GOMA_LOG_LEVEL, overwrite"`
	// Log defines the logging config
	Log Log `yaml:"log,omitempty"`
	// DisableHealthCheckStatus enables or disables health checks for routes.
	DisableHealthCheckStatus bool `yaml:"disableHealthCheckStatus,omitempty"`
	// DisableRouteHealthCheckError enables or disables logging of backend health check errors.
	DisableRouteHealthCheckError bool `yaml:"disableRouteHealthCheckError,omitempty"`
	// DisableDisplayRouteOnStart enables or disables the display of routes during server startup.
	DisableDisplayRouteOnStart bool `yaml:"disableDisplayRouteOnStart,omitempty"`
	// DisableKeepAlive enables or disables the HTTP Keep-Alive functionality.
	DisableKeepAlive bool `yaml:"disableKeepAlive,omitempty"`
	// EnableStrictSlash enables or disables strict routing and trailing slashes.
	//
	// When enabled, the router will match the path with or without a trailing slash.
	EnableStrictSlash bool `yaml:"enableStrictSlash,omitempty"`
	// EnableMetrics enables or disables server metrics collection.
	EnableMetrics bool       `yaml:"enableMetrics,omitempty"`
	EntryPoints   EntryPoint `yaml:"entryPoints,omitempty"`
	// InterceptErrors holds the status codes to intercept backend errors.
	// Deprecated: Use ErrorInterceptor for advanced error handling.
	InterceptErrors []int `yaml:"interceptErrors,omitempty"`
	// ErrorInterceptor provides advanced error-handling configuration for intercepted backend errors.
	ErrorInterceptor middlewares.RouteErrorInterceptor `yaml:"errorInterceptor,omitempty"`
	// Cors defines the global Cross-Origin Resource Sharing (CORS) configuration for the gateway.
	Cors Cors `yaml:"cors,omitempty"`
	// ExtraRoutes specifies additional routes from a directory.
	// Deprecated: Use ExtraConfig for a broader configuration scope.
	ExtraRoutes ExtraRouteConfig `yaml:"extraRoutes,omitempty"`
	// ExtraConfig provides additional configuration, including routes and middleware, from a specified directory.
	ExtraConfig ExtraRouteConfig `yaml:"extraConfig,omitempty"`
	// Routes defines the list of proxy routes.
	Routes []Route `yaml:"routes"`
}
type EntryPoint struct {
	Web       EntryPointAddress `yaml:"web,omitempty"`
	WebSecure EntryPointAddress `yaml:"webSecure,omitempty"`
}
type EntryPointAddress struct {
	Address string `yaml:"address,omitempty"`
}

func (p EntryPoint) Validate() {
	// Check entrypoint ports
	if len(p.Web.Address) > 0 && validateEntrypoint(p.Web.Address) {
		webAddress = p.Web.Address
	}
	if len(p.WebSecure.Address) > 0 && validateEntrypoint(p.WebSecure.Address) {
		webSecureAddress = p.WebSecure.Address

	}
}

type Log struct {
	Level             string `yaml:"level,omitempty"  env:"GOMA_LOG_LEVEL, overwrite"`
	FilePath          string `yaml:"filePath,omitempty" env:"GOMA_LOG_FILE, overwrite"`
	AccessLogFilePath string `yaml:"accessLogFilePath,omitempty" env:"GOMA_ACCESS_LOG_FILE, overwrite"`
}
