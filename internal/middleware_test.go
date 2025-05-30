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
	"fmt"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/pkg/middlewares"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"testing"
)

var rules = []string{"fake", "jwt", "google-jwt", "forwardAuth"}

func TestMiddleware(t *testing.T) {
	TestInit(t)
	middlewares := []Middleware{
		{
			Name:  "basic-auth",
			Type:  BasicAuth,
			Paths: []string{"/", "/admin"},
			Rule: BasicRuleMiddleware{
				Users: []string{
					"admin:admin",
					"user:password",
				},
			},
		},
		{
			Name:  "forwardAuth",
			Type:  forwardAuth,
			Paths: []string{"/*"},
			Rule: ForwardAuthRuleMiddleware{
				AuthURL: "http://localhost:8080/readyz",
			},
		},

		{
			Name:  "jwt",
			Type:  JWTAuth,
			Paths: []string{"/", "/admin"},
			Rule: JWTRuleMiddleware{
				JwksUrl: "https://www.googleapis.com/auth/userinfo.email",
				Secret:  "",
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
		t.Fatalf("Error searching middlewares %s", err.Error())
	}
	log.Printf("Middleware: %v\n", m)

	for _, middleware := range middlewares {

		switch middleware.Type {
		case BasicAuth:
			log.Println("Basic auth")
			basicAuth := BasicRuleMiddleware{}
			if err := goutils.DeepCopy(&basicAuth, middleware.Rule); err != nil {
				t.Fatalf("Error: %v", err.Error())
			}
			log.Printf("Users : %v\n", basicAuth.Users)
		case forwardAuth:
			log.Println("forwardAuth")
			f := ForwardAuthRuleMiddleware{}
			if err := goutils.DeepCopy(&f, middleware.Rule); err != nil {
				t.Fatalf("Error: %v", err.Error())
			}
			err := f.validate()
			if err != nil {
				log.Fatalf("Error in validating forwardAuth: %v ", err)
			}
			log.Printf("Auth URL : %v\n", f.AuthURL)
		case JWTAuth:
			log.Println("JWT auth")
			jwt := &JWTRuleMiddleware{}
			if err := goutils.DeepCopy(jwt, middleware.Rule); err != nil {
				t.Fatalf("Error: %v", err.Error())
			}
			err := jwt.validate()
			if err != nil {
				logger.Error("Error: %s", err.Error())
			}
			log.Printf("JWT authentification valited")
		case OAuth:
			log.Println("OAuth auth")
			oauth := &OauthRulerMiddleware{}
			if err := goutils.DeepCopy(oauth, middleware.Rule); err != nil {
				t.Fatalf("Error: %v, middleware not applied", err.Error())
			}
			err := oauth.validate()
			if err != nil {
				t.Fatalf("Error: %s", err.Error())
			}
			log.Printf("OAuth authentification:  provider %s\n", oauth.Provider)
		case AccessMiddleware:
			log.Println("Access middlewares")
			log.Printf("Access middlewares:  paths: [%s]\n", middleware.Paths)
		default:
			t.Errorf("Unknown middlewares type %s", middleware.Type)

		}
	}

}

func TestFoundMiddleware(t *testing.T) {
	m := getMiddlewares(t)
	middleware, err := GetMiddleware("jwt", m)
	if err != nil {
		t.Errorf("Error getting m %v", err)
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

func TestValidatePassword(t *testing.T) {
	plainPassword := "password"
	bcryptHashedPassword := "$2y$05$Sd/9X/7mphttqqFeBwDz9.WVjU4/urVroHlY3RPXiDDHBIEWojoQm" //  bcrypt hash
	md5HashedPassword := "$apr1$4rM/A28O$Fg37b.l/Ja1OfH8mBA5Ua."                           //  md5crypt hash
	sha1HashedPassword := "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="                              //  SHA1 hash

	valid, err := middlewares.ValidatePassword(plainPassword, bcryptHashedPassword)
	fmt.Printf("BCrypt valid: %v, Error: %v\n", valid, err)

	valid, err = middlewares.ValidatePassword(plainPassword, md5HashedPassword)
	fmt.Printf("MD5 valid: %v, Error: %v\n", valid, err)

	valid, err = middlewares.ValidatePassword(plainPassword, sha1HashedPassword)
	fmt.Printf("SHA1 valid: %v, Error: %v\n", valid, err)

}
