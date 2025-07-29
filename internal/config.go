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
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/certmanager"
	"github.com/jkaninda/goma-gateway/internal/log"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/internal/version"
	"github.com/jkaninda/goma-gateway/util"
	logger2 "github.com/jkaninda/logger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
	"os"
	"strconv"
	"strings"
)

// Config reads config file and returns Gateway
func (*GatewayServer) Config(configFile string, ctx context.Context) (*GatewayServer, error) {
	if util.FileExists(configFile) {
		buf, err := os.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
		util.SetEnv("GOMA_CONFIG_FILE", configFile)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return nil, fmt.Errorf("parsing the configuration file %q: %w", configFile, err)
		}
		return &GatewayServer{
			ctx:         ctx,
			configFile:  configFile,
			certManager: c.GetCertManagerConfig(),
			version:     c.Version,
			gateway:     &c.GatewayConfig,
			middlewares: c.Middlewares,
		}, nil
	}
	logger.Error("Configuration file not found", "file", configFile)
	// Check a default file
	if util.FileExists(ConfigFile) {
		buf, err := os.ReadFile(ConfigFile)
		if err != nil {
			return nil, err

		}
		logger.Info("Using configuration", "file", ConfigFile)
		util.SetEnv("GOMA_CONFIG_FILE", ConfigFile)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return nil, fmt.Errorf("parsing the configuration file %q: %w", ConfigFile, err)
		}
		return &GatewayServer{
			ctx:         ctx,
			certManager: c.GetCertManagerConfig(),
			configFile:  ConfigFile,
			gateway:     &c.GatewayConfig,
			middlewares: c.Middlewares,
		}, nil

	}
	logger.Info("Generating new configuration file...")
	// check if config Directory does exist
	if !util.FolderExists(ConfigDir) {
		err := os.MkdirAll(ConfigDir, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}
	err := initConfig(ConfigFile)
	if err != nil {
		return nil, err
	}
	logger.Info("Generating new configuration file...done", "file", configFile)
	util.SetEnv("GOMA_CONFIG_FILE", ConfigFile)
	buf, err := os.ReadFile(ConfigFile)
	if err != nil {
		return nil, err
	}
	c := &GatewayConfig{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		return nil, fmt.Errorf("in file %q: %w", ConfigFile, err)
	}
	logger.Info("Generating new configuration file...done")
	return &GatewayServer{
		ctx:         ctx,
		configFile:  ConfigFile,
		gateway:     &c.GatewayConfig,
		certManager: c.GetCertManagerConfig(),
		middlewares: c.Middlewares,
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
func (g *GatewayServer) InitLogger() {
	level := strings.ToLower(g.gateway.Log.Level)
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
}

// *************** END DEPRECATIONS ******************************

// initConfig initializes configs
func initConfig(configFile string) error {
	if configFile == "" {
		configFile = GetConfigPaths()
	}
	conf := &GatewayConfig{
		Version: version.ConfigVersion,
		GatewayConfig: Gateway{
			Timeouts: Timeouts{
				Read:  30,
				Write: 30,
				Idle:  30,
			},
			Log: Log{
				Level:    "error",
				FilePath: "",
				Format:   "text",
			},
			Monitoring: Monitoring{
				EnableMetrics:   true,
				EnableReadiness: true,
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
					Methods: []string{"GET", "PATCH", "OPTIONS"},
					Target:  "https://example.com",
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
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
					Path:    "/",
					Hosts:   []string{"app.example.com"},
					Rewrite: "/",
					Backends: Backends{
						Backend{Endpoint: "https://api-1.example.com", Weight: 5},
						Backend{Endpoint: "https://api-2.example.com", Weight: 2},
						Backend{Endpoint: "https://api-3.example.com", Weight: 1},
					},
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
					ErrorInterceptor: middlewares.RouteErrorInterceptor{
						Enabled:     true,
						ContentType: applicationJson,
						Errors: []middlewares.RouteError{
							{
								StatusCode: 403,
								Body:       "403 Forbidden",
							},
							{
								StatusCode: 404,
								Body:       "{\"error\": \"404 Not Found\"}",
							},
							{
								StatusCode: 500,
							},
						},
					},
					Cors: Cors{
						Origins:          []string{"http://localhost:3000", "https://dev.example.com"},
						Headers:          map[string]string{},
						MaxAge:           1728000,
						AllowCredentials: true,
						AllowedHeaders:   []string{"Origin", "Authorization"},
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
					"/*",
				},
				Rule: BasicRuleMiddleware{
					Realm: "Restricted",
					Users: []middlewares.User{
						{Username: "admin", Password: "$2y$05$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO"},
						{Username: "admin", Password: "admin"},
					},
				},
			},
			{
				Name: "block-access",
				Type: AccessMiddleware,
				Paths: []string{
					"/swagger-ui/*",
					"/api-docs/*",
					"/actuator/*",
				},
			}, {
				Name: "block-admin-access",
				Type: AccessMiddleware,
				Paths: []string{
					"/admin/*",
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
	err = os.WriteFile(configFile, yamlData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write config file %s", err)
	}
	return nil
}
func (g *Gateway) Setup(conf string) *Gateway {
	if util.FileExists(conf) {
		buf, err := os.ReadFile(conf)
		if err != nil {
			return &Gateway{}
		}
		util.SetEnv("GOMA_CONFIG_FILE", conf)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			logger.Fatal("Error loading configuration %v", err.Error())
		}
		return &c.GatewayConfig
	}
	return &Gateway{}

}

// rateLimitMiddleware returns RateLimitRuleMiddleware, error
func (rateLimit RateLimitRuleMiddleware) validate() error {
	if rateLimit.RequestsPerUnit == 0 {
		return fmt.Errorf("requests per unit not defined")

	}
	return nil
}

// validate validates JWTRuleMiddleware
func (jwt JWTRuleMiddleware) validate() error {
	if jwt.Secret == "" && jwt.PublicKey == "" && jwt.JwksUrl == "" && jwt.JwksFile == "" {
		return fmt.Errorf("empty Secret, JwksUrl, JwksFile or  PublicKey in jwt auth middlewares")

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

// validate validates BasicRuleMiddleware
func (u UserAgentBlockRuleMiddleware) validate() error {
	if len(u.UserAgents) == 0 {
		return fmt.Errorf("empty userAgents in userAgentBlock  middlewares")
	}
	return nil
}

// validate validates BasicRuleMiddleware
func (basicAuth BasicRuleMiddleware) validate() error {
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
func (l LdapRuleMiddleware) validate() error {
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

// oAuthMiddleware returns OauthRulerMiddleware, error
func (oauthRuler *OauthRulerMiddleware) validate() error {
	if oauthRuler.ClientID == "" || oauthRuler.ClientSecret == "" || oauthRuler.RedirectURL == "" {
		return fmt.Errorf("error parsing yaml: empty clientId/secretId in %s middlewares", oauthRuler)

	}
	return nil
}
func oauthRulerMiddleware(oauth middlewares.Oauth) *OauthRulerMiddleware {
	return &OauthRulerMiddleware{
		ClientID:     oauth.ClientID,
		ClientSecret: oauth.ClientSecret,
		RedirectURL:  oauth.RedirectURL,
		State:        oauth.State,
		Scopes:       oauth.Scopes,
		Provider:     oauth.Provider,
		Endpoint: OauthEndpoint{
			AuthURL:     oauth.Endpoint.AuthURL,
			TokenURL:    oauth.Endpoint.TokenURL,
			UserInfoURL: oauth.Endpoint.UserInfoURL,
			JwksURL:     oauth.Endpoint.JwksURL,
		},
	}
}
func oauth2Config(oauth *OauthRulerMiddleware) *oauth2.Config {
	conf := &oauth2.Config{
		ClientID:     oauth.ClientID,
		ClientSecret: oauth.ClientSecret,
		RedirectURL:  oauth.RedirectURL,
		Scopes:       oauth.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oauth.Endpoint.AuthURL,
			TokenURL: oauth.Endpoint.TokenURL,
		},
	}
	switch oauth.Provider {
	case "google":
		conf.Endpoint = google.Endpoint
		if oauth.Endpoint.UserInfoURL == "" {
			oauth.Endpoint.UserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"
		}
	case "amazon":
		conf.Endpoint = amazon.Endpoint
	case "facebook":
		conf.Endpoint = facebook.Endpoint
		if oauth.Endpoint.UserInfoURL == "" {
			oauth.Endpoint.UserInfoURL = "https://graph.facebook.com/me"
		}
	case "github":
		conf.Endpoint = github.Endpoint
		if oauth.Endpoint.UserInfoURL == "" {
			oauth.Endpoint.UserInfoURL = "https://api.github.com/user/repo"
		}
	case "gitlab":
		conf.Endpoint = gitlab.Endpoint
	default:
		if oauth.Provider != "custom" {
			logger.Error(fmt.Sprintf("Unknown provider: %s", oauth.Provider))
		}

	}
	return conf
}
