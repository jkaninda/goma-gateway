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
	"context"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"os"
)

var cfg *Gateway

type Config struct {
	file string
}
type BasicRule struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Cors struct {
	// Cors Allowed origins,
	//e.g:
	//
	// - http://localhost:80
	//
	// - https://example.com
	Origins []string `yaml:"origins"`
	//
	//e.g:
	//
	//Access-Control-Allow-Origin: '*'
	//
	//    Access-Control-Allow-Methods: 'GET, POST, PUT, DELETE, OPTIONS'
	//
	//    Access-Control-Allow-Cors: 'Content-Type, Authorization'
	Headers map[string]string `yaml:"headers"`
}

// JWTRuler authentication using HTTP GET method
//
// JWTRuler contains the authentication details
type JWTRuler struct {
	// URL contains the authentication URL, it supports HTTP GET method only.
	URL string `yaml:"url"`
	// RequiredHeaders , contains required before sending request to the backend.
	RequiredHeaders []string `yaml:"requiredHeaders"`
	// Headers Add header to the backend from Authentication request's header, depending on your requirements.
	// Key is Http's response header Key, and value  is the backend Request's header Key.
	// In case you want to get headers from Authentication service and inject them to backend request's headers.
	Headers map[string]string `yaml:"headers"`
	// Params same as Headers, contains the request params.
	//
	// Gets authentication headers from authentication request and inject them as request params to the backend.
	//
	// Key is Http's response header Key, and value  is the backend Request's request param Key.
	//
	// In case you want to get headers from Authentication service and inject them to next request's params.
	//
	//e.g: Header X-Auth-UserId to query userId
	Params map[string]string `yaml:"params"`
}

// Middleware defined the route middleware
type Middleware struct {
	//Path contains the name of middleware and must be unique
	Name string `yaml:"name"`
	// Type contains authentication types
	//
	// basic, jwt, auth0, rateLimit
	Type string `yaml:"type"`
	// Rule contains rule type of
	Rule interface{} `yaml:"rule"`
}
type MiddlewareName struct {
	name string `yaml:"name"`
}
type RouteMiddleware struct {
	//Path contains the path to protect
	Path string `yaml:"path"`
	//Rules defines which specific middleware applies to a route path
	Rules []string `yaml:"rules"`
}

// Route defines gateway route
type Route struct {
	// Name defines route name
	Name string `yaml:"name"`
	// Path defines route path
	Path string `yaml:"path"`
	// Rewrite rewrites route path to desired path
	//
	// E.g. /cart to / => It will rewrite /cart path to /
	Rewrite string `yaml:"rewrite"`
	// Destination Defines backend URL
	Destination string `yaml:"destination"`
	// Cors contains the route cors headers
	Cors Cors `yaml:"cors"`
	// DisableHeaderXForward Disable X-forwarded header.
	//
	// [X-Forwarded-Host, X-Forwarded-For, Host, Scheme ]
	//
	// It will not match the backend route
	DisableHeaderXForward bool `yaml:"disableHeaderXForward"`
	// HealthCheck Defines the backend is health check PATH
	HealthCheck string `yaml:"healthCheck"`
	// Blocklist Defines route blacklist
	Blocklist []string `yaml:"blocklist"`
	// Middlewares Defines route middleware from Middleware names
	Middlewares []RouteMiddleware `yaml:"middlewares"`
}

// Gateway contains Goma Proxy Gateway's configs
type Gateway struct {
	// ListenAddr Defines the server listenAddr
	//
	//e.g: localhost:8080
	ListenAddr string `yaml:"listenAddr" env:"GOMA_LISTEN_ADDR, overwrite"`
	// WriteTimeout defines proxy write timeout
	WriteTimeout int `yaml:"writeTimeout" env:"GOMA_WRITE_TIMEOUT, overwrite"`
	// ReadTimeout defines proxy read timeout
	ReadTimeout int `yaml:"readTimeout" env:"GOMA_READ_TIMEOUT, overwrite"`
	// IdleTimeout defines proxy idle timeout
	IdleTimeout int `yaml:"idleTimeout" env:"GOMA_IDLE_TIMEOUT, overwrite"`
	// RateLimiter Defines number of request peer minute
	RateLimiter                  int    `yaml:"rateLimiter" env:"GOMA_RATE_LIMITER, overwrite"`
	AccessLog                    string `yaml:"accessLog" env:"GOMA_ACCESS_LOG, overwrite"`
	ErrorLog                     string `yaml:"errorLog" env:"GOMA_ERROR_LOG=, overwrite"`
	DisableRouteHealthCheckError bool   `yaml:"disableRouteHealthCheckError"`
	//Disable dispelling routes on start
	DisableDisplayRouteOnStart bool `yaml:"disableDisplayRouteOnStart"`
	// Cors contains the proxy global cors
	Cors Cors `yaml:"cors"`
	// Routes defines the proxy routes
	Routes []Route `yaml:"routes"`
}
type GatewayConfig struct {
	GatewayConfig Gateway      `yaml:"gateway"`
	Middlewares   []Middleware `yaml:"middlewares"`
}

// ErrorResponse represents the structure of the JSON error response
type ErrorResponse struct {
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type GatewayServer struct {
	ctx         context.Context
	gateway     Gateway
	middlewares []Middleware
}

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
			return nil, fmt.Errorf("error parsing yaml %q: %w", configFile, err)
		}
		return &GatewayServer{
			ctx:         nil,
			gateway:     c.GatewayConfig,
			middlewares: c.Middlewares,
		}, nil
	}
	logger.Error("Configuration file not found: %v", configFile)
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
			ListenAddr:                   "0.0.0.0:80",
			WriteTimeout:                 15,
			ReadTimeout:                  15,
			IdleTimeout:                  60,
			AccessLog:                    "/dev/Stdout",
			ErrorLog:                     "/dev/stderr",
			DisableRouteHealthCheckError: false,
			DisableDisplayRouteOnStart:   false,
			RateLimiter:                  0,
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
					Name:        "HealthCheck",
					Path:        "/healthy",
					Destination: "http://localhost:8080",
					Rewrite:     "/health",
					HealthCheck: "",
					Cors: Cors{
						Headers: map[string]string{
							"Access-Control-Allow-Headers":     "Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id",
							"Access-Control-Allow-Credentials": "true",
							"Access-Control-Max-Age":           "1728000",
						},
					},
				},
				{
					Name:        "Basic auth",
					Path:        "/basic",
					Destination: "http://localhost:8080",
					Rewrite:     "/health",
					HealthCheck: "",
					Blocklist:   []string{},
					Cors:        Cors{},
					Middlewares: []RouteMiddleware{
						{
							Path:  "/basic/auth",
							Rules: []string{"basic-auth", "google-jwt"},
						},
					},
				},
			},
		},
		Middlewares: []Middleware{
			{
				Name: "basic-auth",
				Type: "basic",
				Rule: BasicRule{
					Username: "goma",
					Password: "goma",
				},
			}, {
				Name: "google-jwt",
				Type: "jwt",
				Rule: JWTRuler{
					URL:     "https://www.googleapis.com/auth/userinfo.email",
					Headers: map[string]string{},
					Params:  map[string]string{},
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
func (middleware Middleware) name() {

}
func ToJWTRuler(input interface{}) (JWTRuler, error) {
	jWTRuler := new(JWTRuler)
	var bytes []byte
	bytes, err := yaml.Marshal(input)
	if err != nil {
		return JWTRuler{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	err = yaml.Unmarshal(bytes, jWTRuler)
	if err != nil {
		return JWTRuler{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	if jWTRuler.URL == "" {
		return JWTRuler{}, fmt.Errorf("error parsing yaml: empty url in jwt auth middleware")

	}
	return *jWTRuler, nil
}

func ToBasicAuth(input interface{}) (BasicRule, error) {
	basicAuth := new(BasicRule)
	var bytes []byte
	bytes, err := yaml.Marshal(input)
	if err != nil {
		return BasicRule{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	err = yaml.Unmarshal(bytes, basicAuth)
	if err != nil {
		return BasicRule{}, fmt.Errorf("error parsing yaml: %v", err)
	}
	if basicAuth.Username == "" || basicAuth.Password == "" {
		return BasicRule{}, fmt.Errorf("error parsing yaml: empty username/password in basic auth middleware")

	}
	return *basicAuth, nil
}
