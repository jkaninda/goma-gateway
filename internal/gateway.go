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
	"strconv"
	"strings"

	goutils "github.com/jkaninda/go-utils"
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
	// Reload configures the on-demand configuration reload endpoint, which lets an
	// external controller (e.g. Miabi) tell the gateway to pull and apply its
	// configuration immediately instead of waiting for the provider poll interval.
	Reload ReloadConfig `yaml:"reload,omitempty"`
	// Analytics configures the per-request event stream the gateway publishes to
	// Redis for an external consumer to roll up into web analytics.
	Analytics AnalyticsConfig `yaml:"analytics,omitempty"`
	// GeoIP configures country resolution at the edge. It is top-level rather
	// than nested under Analytics because three separate features read it: the
	// analytics `country` field, the requests-by-country metric, and the geoBlock
	// middleware — which must work whether or not analytics is enabled.
	GeoIP GeoIPConfig `yaml:"geoip,omitempty"`
	// Routes defines the list of proxy routes.
	Routes []Route `yaml:"routes"`
}

// ReloadConfig configures the token-protected on-demand reload endpoint.
type ReloadConfig struct {
	// Enabled exposes the reload endpoint (default: false). The endpoint is only
	// registered when Enabled is true and a token is configured.
	Enabled bool `yaml:"enabled,omitempty"`
	// Path is the endpoint path (default: /gateway/reload).
	Path string `yaml:"path,omitempty"`
	// Token is the bearer token required in the Authorization header
	// ("Authorization: Bearer <token>"). Prefer setting it via the
	// GOMA_RELOAD_TOKEN environment variable rather than in the config file.
	Token string `yaml:"token,omitempty"`
	// Host optionally restricts the endpoint to requests with this Host header.
	Host string `yaml:"host,omitempty"`
}

// AnalyticsConfig configures the per-request event stream Goma publishes to
// Redis (a consumer such as Miabi rolls it up into traffic/web analytics).
//
// Events carry no raw client IP — only a daily-salted visitor id and, when a
// GeoIP database is available, a country resolved at the edge.
//
// Every field can also be set from the environment, which takes precedence, so
// an existing GOMA_ANALYTICS_* deployment keeps working unchanged and a
// container can still override what the config file says.
type AnalyticsConfig struct {
	// Enabled turns the emitter on (default: false). Redis must be configured —
	// it is the transport — or analytics stays off with a warning.
	// Env: GOMA_ANALYTICS_ENABLED
	Enabled bool `yaml:"enabled,omitempty"`
	// Stream is the Redis stream events are published to (default:
	// goma:analytics). The consumer must read the same stream and Redis database.
	// Env: GOMA_ANALYTICS_STREAM
	Stream string `yaml:"stream,omitempty"`
	// Sample is the fraction of requests recorded, 0..1 (default: 1 = all). Values
	// <= 0 or >= 1 record everything.
	// Env: GOMA_ANALYTICS_SAMPLE
	Sample float64 `yaml:"sample,omitempty"`
	// MaxLen approximately caps the stream length so a lagging or absent consumer
	// cannot grow Redis unbounded (default: 1000000).
	// Env: GOMA_ANALYTICS_MAXLEN
	MaxLen int64 `yaml:"maxLen,omitempty"`
	// GatewayID labels events with the gateway that served them, for installs
	// running more than one edge.
	// Env: GOMA_GATEWAY_ID
	GatewayID string `yaml:"gatewayId,omitempty"`
}

// GeoIPConfig points at the MaxMind-format database used to resolve a request's
// country at the edge. Goma ships and downloads no database — every GeoIP
// dataset carries license terms only the operator can accept — so this is empty
// by default and country resolution simply stays off.
type GeoIPConfig struct {
	// Database is the path to a .mmdb file. When empty, Goma tries
	// /etc/goma/country.mmdb then /etc/goma/GeoLite2-Country.mmdb, and leaves
	// country resolution off if neither opens.
	// Env: GOMA_GEOIP_DB
	Database string `yaml:"database,omitempty"`
}

// databasePath returns the explicit database path, or "" to search the
// well-known locations. GOMA_GEOIP_DB overrides the config file.
func (g GeoIPConfig) databasePath() string {
	return strings.TrimSpace(goutils.Env("GOMA_GEOIP_DB", g.Database))
}

// analyticsEnabled reports whether the emitter should start, with
// GOMA_ANALYTICS_ENABLED taking precedence over the config file.
func (a AnalyticsConfig) analyticsEnabled() bool {
	return goutils.EnvBool("GOMA_ANALYTICS_ENABLED", a.Enabled)
}

// stream returns the target Redis stream, env first, then config, then default.
func (a AnalyticsConfig) streamName() string {
	if s := goutils.Env("GOMA_ANALYTICS_STREAM", a.Stream); s != "" {
		return s
	}
	return defaultAnalyticsStream
}

// sampleRate returns the sampling fraction. A malformed env value falls back to
// the config value rather than silently recording nothing.
func (a AnalyticsConfig) sampleRate() float64 {
	if raw := goutils.Env("GOMA_ANALYTICS_SAMPLE", ""); raw != "" {
		if v, err := strconv.ParseFloat(raw, 64); err == nil {
			return v
		}
		logger.Warn("Invalid GOMA_ANALYTICS_SAMPLE, ignoring", "value", raw)
	}
	if a.Sample > 0 {
		return a.Sample
	}
	return 1
}

// streamMaxLen returns the approximate stream cap. Non-positive values are
// rejected at both layers: an uncapped stream is how a stalled consumer fills
// Redis.
func (a AnalyticsConfig) streamMaxLen() int64 {
	if raw := goutils.Env("GOMA_ANALYTICS_MAXLEN", ""); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil && v > 0 {
			return v
		}
		logger.Warn("Invalid GOMA_ANALYTICS_MAXLEN, ignoring", "value", raw)
	}
	if a.MaxLen > 0 {
		return a.MaxLen
	}
	return defaultAnalyticsMaxLen
}

// gatewayIdentifier returns the label stamped on emitted events.
func (a AnalyticsConfig) gatewayIdentifier() string {
	return goutils.Env("GOMA_GATEWAY_ID", a.GatewayID)
}

// reloadToken returns the configured reload token, with the GOMA_RELOAD_TOKEN
// environment variable taking precedence over the config file value.
func (r ReloadConfig) reloadToken() string {
	return goutils.Env("GOMA_RELOAD_TOKEN", r.Token)
}

// reloadPath returns the configured endpoint path, defaulting to /gateway/reload.
func (r ReloadConfig) reloadPath() string {
	if r.Path != "" {
		return r.Path
	}
	return "/gateway/reload"
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
	webAddr := goutils.Env("GOMA_ENTRYPOINT_WEB_ADDRESS", p.Web.Address)
	// Validate web entry point
	if addr := webAddr; addr != "" {
		if validateEntrypoint(addr) {
			webAddress = addr
		} else {
			logger.Fatal("Error, invalid web address", "address", addr)
		}
	}
	webSecureAddr := goutils.Env("GOMA_ENTRYPOINT_WEB_SECURE_ADDRESS", p.WebSecure.Address)
	// Validate webSecure entry point
	if addr := webSecureAddr; addr != "" {
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

	// VisitorTTL is how long a visitor keeps counting towards the real-time
	// visitors gauge after their last request, as a duration (default: 5m).
	VisitorTTL string `yaml:"visitorTTL,omitempty"`

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
	// TTL is the DNS cache entry lifetime in seconds (default: 300).
	TTL int `yaml:"ttl,omitempty"`
	// ClearOnReload, when enabled, flushes the local DNS cache after the routes
	// are reloaded (auto-reload or on configuration changes). Default: false.
	ClearOnReload bool `yaml:"clearOnReload,omitempty"`
	// Resolver optionally sets custom DNS server addresses (e.g. "1.1.1.1",
	// "8.8.8.8:53"). When empty, the system default resolver is used.
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
