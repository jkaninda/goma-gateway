package pkg

/*
Copyright 2024 Jonas Kaninda.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may get a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/
import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

// printRoute prints routes
func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Route", "Rewrite", "Destination"})
	for _, route := range routes {
		if len(route.Backends) > 0 {
			t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, fmt.Sprintf("backends: [%d]", len(route.Backends))})

		} else {
			t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, route.Destination})
		}
	}
	fmt.Println(t.Render())
}

// getRealIP gets user real IP
func getRealIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

// loadTLS loads TLS Certificate
func loadTLS(cert, key string) (*tls.Config, error) {
	if cert == "" && key == "" {
		return nil, fmt.Errorf("no certificate or key file provided")
	}
	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		logger.Error("Error loading server certificate: %v", err)
		return nil, err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	return tlsConfig, nil
}
func (oauth *OauthRulerMiddleware) getUserInfo(token *oauth2.Token) (UserInfo, error) {
	oauthConfig := oauth2Config(oauth)
	// Call the user info endpoint with the token
	client := oauthConfig.Client(context.Background(), token)
	resp, err := client.Get(oauth.Endpoint.UserInfoURL)
	if err != nil {
		return UserInfo{}, err
	}
	defer resp.Body.Close()

	// Parse the user info
	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return UserInfo{}, err
	}

	return userInfo, nil
}
func createJWT(email, jwtSecret string) (string, error) {
	// Define JWT claims
	claims := jwt.MapClaims{
		"email": email,
		"exp":   jwt.TimeFunc().Add(time.Hour * 24).Unix(), // Token expiration
		"iss":   "Goma-Gateway",                            // Issuer claim
	}

	// Create a new token with HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with a secret
	signedToken, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// healthCheckRoutes creates []Health
func healthCheckRoutes(routes []Route) []Health {
	var healthRoutes []Health
	for _, route := range routes {
		if len(route.HealthCheck.Path) > 0 {
			timeout, _ := util.ParseDuration("")
			if len(route.HealthCheck.Timeout) > 0 {
				d1, err1 := util.ParseDuration(route.HealthCheck.Timeout)
				if err1 != nil {
					logger.Error("Health check timeout is invalid: %s", route.HealthCheck.Timeout)
				}
				timeout = d1
			}
			if len(route.Backends) > 0 {
				for index, backend := range route.Backends {
					health := Health{
						Name:            fmt.Sprintf("%s - [%d]", route.Name, index),
						URL:             backend + route.HealthCheck.Path,
						TimeOut:         timeout,
						HealthyStatuses: route.HealthCheck.HealthyStatuses,
					}
					healthRoutes = append(healthRoutes, health)
				}

			} else {
				health := Health{
					Name:            route.Name,
					URL:             route.Destination + route.HealthCheck.Path,
					TimeOut:         timeout,
					HealthyStatuses: route.HealthCheck.HealthyStatuses,
				}
				healthRoutes = append(healthRoutes, health)
			}
		} else {
			logger.Debug("Route %s's healthCheck is undefined", route.Name)
		}
	}
	return healthRoutes
}
