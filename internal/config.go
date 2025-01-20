package internal

/*
Copyright 2024 Jonas Kaninda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import (
	"context"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
)

// Config reads config file and returns Gateway
func (GatewayServer) Config(configFile string, ctx context.Context) (*GatewayServer, error) {
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
			version:     c.Version,
			gateway:     c.GatewayConfig,
			middlewares: c.Middlewares,
		}, nil
	}
	logger.Error("Configuration file not found: %v", configFile)
	// Check a default file
	if util.FileExists(ConfigFile) {
		buf, err := os.ReadFile(ConfigFile)
		if err != nil {
			return nil, err

		}
		logger.Info("Using configuration file: %s", ConfigFile)
		util.SetEnv("GOMA_CONFIG_FILE", ConfigFile)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return nil, fmt.Errorf("parsing the configuration file %q: %w", ConfigFile, err)
		}
		return &GatewayServer{
			ctx:         ctx,
			configFile:  ConfigFile,
			gateway:     c.GatewayConfig,
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
	logger.Info("Generating new configuration file...done")
	logger.Info("Server configuration file is unavailable at %s", ConfigFile)
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
		gateway:     c.GatewayConfig,
		middlewares: c.Middlewares,
	}, nil
}

// SetEnv sets environment variables
func (gatewayServer GatewayServer) SetEnv() {
	util.SetEnv("GOMA_LOG_LEVEL", gatewayServer.gateway.LogLevel)
	util.SetEnv("GOMA_ERROR_LOG", gatewayServer.gateway.ErrorLog)
	util.SetEnv("GOMA_ACCESS_LOG", gatewayServer.gateway.AccessLog)

}

// validateRoutes validates routes
func validateRoutes(gateway Gateway, routes []Route) []Route {
	for _, route := range routes {
		validateRoute(route)
	}

	for i := range routes {
		handleDeprecations(&routes[i])
		mergeGatewayErrorInterceptor(&routes[i], gateway.ErrorInterceptor)
	}

	return routes
}

func validateRoute(route Route) {
	if len(route.Name) == 0 {
		logger.Fatal("Route name is required")
	}
	if len(route.Destination) == 0 && len(route.Backends) == 0 {
		logger.Fatal("Route %s : destination or backends should not be empty", route.Name)
	}
}
func handleDeprecations(route *Route) {
	if route.DisableHostFording {
		logger.Warn("Deprecation: disableHostFording is deprecated, please rename it to disableHostForwarding")
		route.DisableHostForwarding = true
	}

	if len(route.InterceptErrors) > 0 {
		logger.Warn("Route InterceptErrors is deprecated, please use errorInterceptor instead.")
		for _, status := range route.InterceptErrors {
			route.ErrorInterceptor.Errors = append(route.ErrorInterceptor.Errors, middlewares.RouteError{
				Status: status,
				Body:   http.StatusText(status),
			})
		}
		route.ErrorInterceptor.Enabled = true
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

func GetConfigPaths() string {
	return util.GetStringEnv("GOMA_CONFIG_FILE", ConfigFile)
}

// InitConfig initializes configs
func InitConfig(configFile string) error {
	return initConfig(configFile)

}
func handleGatewayDeprecations(gateway *Gateway) {
	if len(gateway.ExtraConfig.Directory) == 0 {
		gateway.ExtraConfig.Directory = ExtraDir
	}
	if len(gateway.ExtraRoutes.Directory) > 0 {
		logger.Warn("Deprecation: extraRoutes is deprecated, please rename it to extraConfig.")
		gateway.ExtraConfig.Directory = gateway.ExtraRoutes.Directory
	}

}

// initConfig initializes configs
func initConfig(configFile string) error {
	if configFile == "" {
		configFile = GetConfigPaths()
	}
	conf := &GatewayConfig{
		Version: util.ConfigVersion,
		GatewayConfig: Gateway{
			WriteTimeout: 15,
			ReadTimeout:  15,
			IdleTimeout:  30,
			ExtraConfig: ExtraRouteConfig{
				Directory: ExtraDir,
				Watch:     false,
			},
			Routes: []Route{
				{
					Name:        "Example",
					Path:        "/",
					Methods:     []string{"GET", "PATCH", "OPTIONS"},
					Destination: "https://example.com",
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
					DisableHostForwarding: true,
					Middlewares:           []string{"block-access"},
				},
				{
					Name:    "round-robin-load-balancing",
					Path:    "/load-balancing",
					Methods: []string{"GET", "OPTIONS"},
					Backends: Backends{
						Backend{EndPoint: "https://example.com"},
						Backend{EndPoint: "https://example1.com"},
						Backend{EndPoint: "https://example2.com"},
					},
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
					DisableHostForwarding: true,
					Middlewares:           []string{"block-access"},
				},
				{
					Name: "weighted-load-balancing",
					Path: "/load-balancing2",
					Backends: Backends{
						Backend{EndPoint: "https://example.com", Weight: 5},
						Backend{EndPoint: "https://example1.com", Weight: 2},
						Backend{EndPoint: "https://example2.com", Weight: 1},
					},
					Rewrite:               "/",
					DisableHostForwarding: false,
					ErrorInterceptor: middlewares.RouteErrorInterceptor{
						Enabled:     true,
						ContentType: applicationJson,
						Errors: []middlewares.RouteError{
							{
								Status: 403,
								Body:   "403 Forbidden",
							},
							{
								Status: 404,
								Body:   "{\"error\": \"404 Not Found\"}",
							},
							{
								Status: 500,
							},
						},
					},
					Cors: Cors{
						Origins: []string{"http://localhost:3000", "https://dev.example.com"},
						Headers: map[string]string{
							"Access-Control-Allow-Headers":     "Origin, Authorization",
							"Access-Control-Allow-Credentials": "true",
							"Access-Control-Max-Age":           "1728000",
						},
					},
					Middlewares: []string{"basic-auth", "block-access"},
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
					Users: []string{
						"admin:$2y$05$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO",
						"admin:admin",
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
	}
	yamlData, err := yaml.Marshal(&conf)
	if err != nil {
		return fmt.Errorf("serializing configuration %v\n", err.Error())
	}
	err = os.WriteFile(configFile, yamlData, 0644)
	if err != nil {
		return fmt.Errorf("unable to write config file %s\n", err)
	}
	return nil
}
func (Gateway) Setup(conf string) *Gateway {
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
	if jwt.Secret == "" && jwt.PublicKey == "" && jwt.JwksUrl == "" {
		return fmt.Errorf("empty Secret, JwksUrl or  PublicKey in jwt auth middlewares")

	}
	return nil
}

// validate validates JWTRuleMiddleware
func (f ForwardAuthRuleMiddleware) validate() error {
	if f.AuthURL == "" {
		return fmt.Errorf("error parsing yaml: empty url in forwardAuth middlewares")

	}
	return nil
}

// validate validates BasicRuleMiddleware
func (basicAuth BasicRuleMiddleware) validate() error {
	user := fmt.Sprintf("%s:%s", basicAuth.Username, basicAuth.Password)
	if user != "" {
		basicAuth.Users = append(basicAuth.Users, user)
	}
	if len(basicAuth.Users) == 0 {
		return fmt.Errorf("empty users in basic auth middlewares")
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
		JWTSecret:    oauth.JWTSecret,
		Provider:     oauth.Provider,
		Endpoint: OauthEndpoint{
			AuthURL:     oauth.Endpoint.AuthURL,
			TokenURL:    oauth.Endpoint.TokenURL,
			UserInfoURL: oauth.Endpoint.UserInfoURL,
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
			logger.Error("Unknown provider: %s", oauth.Provider)
		}

	}
	return conf
}
