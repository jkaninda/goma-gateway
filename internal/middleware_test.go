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
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"testing"
)

const MidName = "google-jwt"

var rules = []string{"fake", "jwt", "google-jwt"}

func TestMiddleware(t *testing.T) {
	TestInit(t)
	middlewares := []Middleware{
		{
			Name:  "basic-auth",
			Type:  BasicAuth,
			Paths: []string{"/", "/admin"},
			Rule: BasicRuleMiddleware{
				Username: "goma",
				Password: "goma",
			},
		},
		{
			Name:  "forbidden path access",
			Type:  AccessMiddleware,
			Paths: []string{"/", "/admin"},
			Rule: BasicRuleMiddleware{
				Username: "goma",
				Password: "goma",
			},
		},

		{
			Name:  "jwt",
			Type:  JWTAuth,
			Paths: []string{"/", "/admin"},
			Rule: JWTRuleMiddleware{
				URL:     "https://www.googleapis.com/auth/userinfo.email",
				Headers: map[string]string{},
				Params:  map[string]string{},
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
			Name: "api-forbidden-paths",
			Type: AccessMiddleware,
			Paths: []string{
				"/swagger-ui/*",
				"/v2/swagger-ui/*",
				"/api-docs/*",
				"/actuator/*",
			},
		},
	}
	yamlData, err := yaml.Marshal(&middlewares)
	if err != nil {
		t.Fatalf("Error serializing configuration %v", err.Error())
	}
	err = os.WriteFile(configFile, yamlData, 0644)
	if err != nil {
		t.Fatalf("Unable to write config file %s", err)
	}
	log.Printf("Config file written to %s", configFile)
}

func TestReadMiddleware(t *testing.T) {
	TestMiddleware(t)
	middlewares := getMiddlewares(t)
	m, err := getMiddleware(rules, middlewares)
	if err != nil {
		t.Fatalf("Error searching middleware %s", err.Error())
	}
	log.Printf("Middleware: %v\n", m)

	for _, middleware := range middlewares {

		switch middleware.Type {
		case BasicAuth:
			log.Println("Basic auth")
			basicAuth, err := getBasicAuthMiddleware(middleware.Rule)
			if err != nil {
				log.Fatalln("error:", err)
			}
			log.Printf("Username: %s and password: %s\n", basicAuth.Username, basicAuth.Password)
		case JWTAuth:
			log.Println("JWT auth")
			jwt, err := getJWTMiddleware(middleware.Rule)
			if err != nil {
				log.Fatalln("error:", err)
			}
			log.Printf("JWT authentification URL is %s\n", jwt.URL)
		case OAuth:
			log.Println("OAuth auth")
			oauth, err := oAuthMiddleware(middleware.Rule)
			if err != nil {
				log.Fatalln("error:", err)
			}
			log.Printf("OAuth authentification:  provider %s\n", oauth.Provider)
		case AccessMiddleware:
			log.Println("Access middleware")
			log.Printf("Access middleware:  paths: [%s]\n", middleware.Paths)
		default:
			t.Errorf("Unknown middleware type %s", middleware.Type)

		}
	}

}

func TestFoundMiddleware(t *testing.T) {
	middlewares := getMiddlewares(t)
	middleware, err := GetMiddleware("jwt", middlewares)
	if err != nil {
		t.Errorf("Error getting middleware %v", err)
	}
	fmt.Println(middleware.Type)
}

func getMiddlewares(t *testing.T) []Middleware {
	buf, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("Unable to read config file %s", configFile)
	}
	c := &[]Middleware{}
	err = yaml.Unmarshal(buf, c)
	if err != nil {
		t.Fatalf("Unable to parse config file %s", configFile)
	}
	return *c
}
