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
	logger.Info("Server configuration file is available at %s", ConfigFile)
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

func GetConfigPaths() string {
	return util.GetStringEnv("GOMA_CONFIG_FILE", ConfigFile)
}

// InitConfig initializes configs
func InitConfig(configFile string) error {
	return initConfig(configFile)

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
			Routes: []Route{
				{
					Name:        "Example",
					Path:        "/",
					Methods:     []string{"GET"},
					Destination: "https://example.com",
					Rewrite:     "/",
					HealthCheck: RouteHealthCheck{
						Path:            "/",
						Interval:        "30s",
						Timeout:         "10s",
						HealthyStatuses: []int{200, 404},
					},
					DisableHostFording: true,
					Middlewares:        []string{"block-access"},
				},
				{
					Name: "Load balancer",
					Path: "/protected",
					Backends: []string{
						"https://example.com",
						"https://example2.com",
						"https://example3.com",
					},
					Rewrite:     "/",
					HealthCheck: RouteHealthCheck{},
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
					Username: "admin",
					Password: "admin",
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
func rateLimitMiddleware(input interface{}) (RateLimitRuleMiddleware, error) {
	rateLimit := new(RateLimitRuleMiddleware)
	var bytes []byte
	bytes, err := yaml.Marshal(input)
	if err != nil {
		return RateLimitRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	err = yaml.Unmarshal(bytes, rateLimit)
	if err != nil {
		return RateLimitRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	if rateLimit.RequestsPerUnit == 0 {
		return RateLimitRuleMiddleware{}, fmt.Errorf("requests per unit not defined")

	}
	return *rateLimit, nil
}

// getJWTMiddleware returns JWTRuleMiddleware,error
func getJWTMiddleware(input interface{}) (JWTRuleMiddleware, error) {
	jWTRuler := new(JWTRuleMiddleware)
	var bytes []byte
	bytes, err := yaml.Marshal(input)
	if err != nil {
		return JWTRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	err = yaml.Unmarshal(bytes, jWTRuler)
	if err != nil {
		return JWTRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	if jWTRuler.URL == "" {
		return JWTRuleMiddleware{}, fmt.Errorf("error parsing yaml: empty url in jwt auth middlewares")

	}
	return *jWTRuler, nil
}

// getBasicAuthMiddleware returns BasicRuleMiddleware,error
func getBasicAuthMiddleware(input interface{}) (BasicRuleMiddleware, error) {
	basicAuth := new(BasicRuleMiddleware)
	var bytes []byte
	bytes, err := yaml.Marshal(input)
	if err != nil {
		return BasicRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	err = yaml.Unmarshal(bytes, basicAuth)
	if err != nil {
		return BasicRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	if basicAuth.Username == "" || basicAuth.Password == "" {
		return BasicRuleMiddleware{}, fmt.Errorf("error parsing yaml: empty username/password in %s middlewares", basicAuth)

	}
	return *basicAuth, nil
}
func getAccessPoliciesMiddleware(input interface{}) (AccessPolicyRuleMiddleware, error) {
	a := new(AccessPolicyRuleMiddleware)
	var bytes []byte
	bytes, err := yaml.Marshal(input)
	if err != nil {
		return AccessPolicyRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	err = yaml.Unmarshal(bytes, a)
	if err != nil {
		return AccessPolicyRuleMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	if len(a.SourceRanges) == 0 {
		return AccessPolicyRuleMiddleware{}, fmt.Errorf("empty sourceRanges")

	}
	for _, ip := range a.SourceRanges {
		isIP, isCIDR := isIPOrCIDR(ip)
		if isIP {
			if !validateIPAddress(ip) {
				return AccessPolicyRuleMiddleware{}, fmt.Errorf("invalid ip address")
			}
		}
		if isCIDR {
			if !validateCIDR(ip) {
				return AccessPolicyRuleMiddleware{}, fmt.Errorf("invalid cidr address")
			}
		}

	}
	return *a, nil
}

// oAuthMiddleware returns OauthRulerMiddleware, error
func oAuthMiddleware(input interface{}) (OauthRulerMiddleware, error) {
	oauthRuler := new(OauthRulerMiddleware)
	var bytes []byte
	bytes, err := yaml.Marshal(input)
	if err != nil {
		return OauthRulerMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	err = yaml.Unmarshal(bytes, oauthRuler)
	if err != nil {
		return OauthRulerMiddleware{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	if oauthRuler.ClientID == "" || oauthRuler.ClientSecret == "" || oauthRuler.RedirectURL == "" {
		return OauthRulerMiddleware{}, fmt.Errorf("error parsing yaml: empty clientId/secretId in %s middlewares", oauthRuler)

	}
	return *oauthRuler, nil
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
