package pkg

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
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/middleware"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
	"os"
)

var cfg *Gateway

// Config reads config file and returns Gateway
func (GatewayServer) Config(configFile string) (*GatewayServer, error) {
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
			ctx:         nil,
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
		util.SetEnv("GOMA_CONFIG_FILE", configFile)
		c := &GatewayConfig{}
		err = yaml.Unmarshal(buf, c)
		if err != nil {
			return nil, fmt.Errorf("parsing the configuration file %q: %w", ConfigFile, err)
		}
		return &GatewayServer{
			ctx:         nil,
			gateway:     c.GatewayConfig,
			middlewares: c.Middlewares,
		}, nil

	}
	logger.Info("Generating new configuration file...")
	initConfig(ConfigFile)
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
	logger.Info("Starting server with default configuration")
	return &GatewayServer{
		ctx:         nil,
		gateway:     c.GatewayConfig,
		middlewares: c.Middlewares,
	}, nil
}
func GetConfigPaths() string {
	return util.GetStringEnv("GOMAY_CONFIG_FILE", ConfigFile)
}
func InitConfig(cmd *cobra.Command) {
	configFile, _ := cmd.Flags().GetString("output")
	if configFile == "" {
		configFile = GetConfigPaths()
	}
	initConfig(configFile)
	return

}
func initConfig(configFile string) {
	if configFile == "" {
		configFile = GetConfigPaths()
	}
	conf := &GatewayConfig{
		GatewayConfig: Gateway{
			WriteTimeout:                 15,
			ReadTimeout:                  15,
			IdleTimeout:                  60,
			AccessLog:                    "/dev/Stdout",
			ErrorLog:                     "/dev/stderr",
			DisableRouteHealthCheckError: false,
			DisableDisplayRouteOnStart:   false,
			RateLimiter:                  0,
			InterceptErrors:              []int{405, 500},
			Cors: Cors{
				Origins: []string{"http://localhost:8080", "https://example.com"},
				Headers: map[string]string{
					"Access-Control-Allow-Headers":     "Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id",
					"Access-Control-Allow-Credentials": "true",
					"Access-Control-Max-Age":           "1728000",
				},
			},
			Routes: []Route{
				{
					Name:        "Public",
					Path:        "/public",
					Destination: "https://example.com",
					Rewrite:     "/",
					HealthCheck: "",
					Middlewares: []string{"api-forbidden-paths"},
				},
				{
					Name:        "Basic auth",
					Path:        "/protected",
					Destination: "https://example.com",
					Rewrite:     "/",
					HealthCheck: "",
					Cors: Cors{
						Origins: []string{"http://localhost:3000", "https://dev.example.com"},
						Headers: map[string]string{
							"Access-Control-Allow-Headers":     "Origin, Authorization",
							"Access-Control-Allow-Credentials": "true",
							"Access-Control-Max-Age":           "1728000",
						},
					},
					Middlewares: []string{"basic-auth", "api-forbidden-paths"},
				},
				{
					Name:        "Hostname example",
					Host:        "http://example.localhost",
					Path:        "/",
					Destination: "https://example.com",
					Rewrite:     "/",
					HealthCheck: "",
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
			}, {
				Name: "jwt",
				Type: JWTAuth,
				Paths: []string{
					"/protected-access",
					"/example-of-jwt",
				},
				Rule: JWTRuleMiddleware{
					URL: "https://example.com/auth/userinfo",
					RequiredHeaders: []string{
						"Authorization",
					},
					Headers: map[string]string{},
					Params:  map[string]string{},
				},
			},
			{
				Name: "api-forbidden-paths",
				Type: AccessMiddleware,
				Paths: []string{
					"/swagger-ui/*",
					"/v2/swagger-ui/*",
					"/api-docs/*",
					"/internal/*",
					"/actuator/*",
				},
			},
			{
				Name: "oauth-google",
				Type: OAuth,
				Paths: []string{
					"/protected",
					"/example-of-oauth",
				},
				Rule: OauthRulerMiddleware{
					ClientID:     "xxx",
					ClientSecret: "xxx",
					Provider:     "google",
					JWTSecret:    "your-strong-jwt-secret | It's optional",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes: []string{"https://www.googleapis.com/auth/userinfo.email",
						"https://www.googleapis.com/auth/userinfo.profile"},
					Endpoint: OauthEndpoint{},
					State:    "randomStateString",
				},
			},
			{
				Name: "oauth-authentik",
				Type: OAuth,
				Paths: []string{
					"/protected",
					"/example-of-oauth",
				},
				Rule: OauthRulerMiddleware{
					ClientID:     "xxx",
					ClientSecret: "xxx",
					RedirectURL:  "http://localhost:8080/callback",
					Scopes:       []string{"email", "openid"},
					JWTSecret:    "your-strong-jwt-secret | It's optional",
					Endpoint: OauthEndpoint{
						AuthURL:     "https://authentik.example.com/application/o/authorize/",
						TokenURL:    "https://authentik.example.com/application/o/token/",
						UserInfoURL: "https://authentik.example.com/application/o/userinfo/",
					},
					State: "randomStateString",
				},
			},
		},
	}
	yamlData, err := yaml.Marshal(&conf)
	if err != nil {
		logger.Fatal("Error serializing configuration %v", err.Error())
	}
	err = os.WriteFile(configFile, yamlData, 0644)
	if err != nil {
		logger.Fatal("Unable to write config file %s", err)
	}
	logger.Info("Configuration file has been initialized successfully")
}
func Get() *Gateway {
	if cfg == nil {
		c := &Gateway{}
		c.Setup(GetConfigPaths())
		cfg = c
	}
	return cfg
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
		return JWTRuleMiddleware{}, fmt.Errorf("error parsing yaml: empty url in jwt auth middleware")

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
		return BasicRuleMiddleware{}, fmt.Errorf("error parsing yaml: empty username/password in %s middleware", basicAuth)

	}
	return *basicAuth, nil
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
		return OauthRulerMiddleware{}, fmt.Errorf("error parsing yaml: empty clientId/secretId in %s middleware", oauthRuler)

	}
	return *oauthRuler, nil
}
func oauthRulerMiddleware(oauth middleware.Oauth) *OauthRulerMiddleware {
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
