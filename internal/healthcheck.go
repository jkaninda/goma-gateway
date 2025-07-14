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
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/version"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/robfig/cron/v3"
	"io"
	"net/http"
	"net/url"
	"slices"
)

// Check checks route heath check
func (health Health) Check() error {
	// Parse the health check URL
	healthCheckURL, err := url.Parse(health.URL)
	if err != nil {
		return fmt.Errorf("error parsing HealthCheck URL: %v", err)
	}

	// Create the HTTP request
	healthReq, err := health.createHealthCheckRequest(healthCheckURL)
	if err != nil {
		return fmt.Errorf("error creating HealthCheck request for route %s: %v", health.Name, err)
	}

	// Create the HTTP client with custom transport
	client := health.createHTTPClient()

	// Perform the HTTP request
	healthResp, err := client.Do(healthReq)
	if err != nil {
		logger.Debug("Error performing HealthCheck request for route %s: %v", health.Name, err)
		return fmt.Errorf("error performing HealthCheck request: %v", err)
	}
	defer health.closeResponseBody(healthResp.Body)

	// Validate the response status code
	if err := health.validateStatusCode(healthResp.StatusCode); err != nil {
		logger.Debug("Health check failed for route %s: %v", health.Name, err)
		return err
	}

	return nil
}

// createHealthCheckRequest creates an HTTP request for the health check
func (health Health) createHealthCheckRequest(healthCheckURL *url.URL) (*http.Request, error) {
	req, err := http.NewRequest("GET", healthCheckURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("goma-gateway/%s", version.Version))
	return req, nil
}

// createHTTPClient creates an HTTP client with custom transport and timeout
func (health Health) createHTTPClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: health.InsecureSkipVerify, // Skip SSL certificate verification
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   health.TimeOut,
	}
}

// closeResponseBody closes the response body and logs any errors
func (health Health) closeResponseBody(body io.ReadCloser) {
	if err := body.Close(); err != nil {
		logger.Debug("Error closing HealthCheck response body", "error", err)
	}
}

// validateStatusCode checks if the response status code is healthy
func (health Health) validateStatusCode(statusCode int) error {
	if len(health.HealthyStatuses) > 0 {
		if !slices.Contains(health.HealthyStatuses, statusCode) {
			return fmt.Errorf("health check failed with status code %d", statusCode)
		}
	} else if statusCode >= 400 {
		return fmt.Errorf("health check failed with status code %d", statusCode)
	}
	return nil
}

// routesHealthCheck creates healthcheck job
func routesHealthCheck(routes []Route, stopChan chan struct{}) {
	for _, health := range healthCheckRoutes(routes) {
		go func(health Health) {
			for {
				select {
				case <-stopChan:
					logger.Debug(fmt.Sprintf("Stopping health check for route: %s", health.Name))
					return
				default:
					err := health.createHealthCheckJob(stopChan)
					if err != nil {
						logger.Error("Error creating healthcheck job ", "error", err)
						return
					}
				}
			}
		}(health)
	}
}

// createHealthCheckJob creates a health check job and stops it when a signal is received on stopChan
func (health Health) createHealthCheckJob(stopChan chan struct{}) error {
	interval := "30s"
	if len(health.Interval) > 0 {
		interval = health.Interval
	}

	// Create cron expression
	expression := fmt.Sprintf("@every %s", interval)
	if !util.IsValidCronExpression(expression) {
		logger.Error("Health check interval is invalid", "interval", interval)
		logger.Info("Route health check ignored")
		return fmt.Errorf("health check interval is invalid: %s", interval)
	}

	// Create a new cron instance
	c := cron.New()

	// Add the health check function to the cron scheduler
	_, err := c.AddFunc(expression, func() {
		err := health.Check()
		if err != nil {
			logger.Error("Route is unhealthy,", "route", health.Name, "error", err)
			return
		}
		logger.Debug("Route is healthy", "route", health.Name)
	})
	if err != nil {
		return err
	}

	// Start the cron scheduler
	c.Start()

	// Ensure the cron scheduler is stopped when the function exits
	defer c.Stop()

	// Wait for a stop signal on the stopChan
	<-stopChan
	logger.Debug(fmt.Sprintf("Stopping health check job for route: %s", health.Name))
	return nil
}

// healthCheckRoutes creates and returns []Health
func healthCheckRoutes(routes []Route) []Health {
	var healthRoutes []Health
	for _, route := range routes {
		if len(route.HealthCheck.Path) != 0 && route.Enabled {
			timeout, _ := util.ParseDuration("")
			if len(route.HealthCheck.Timeout) > 0 {
				d1, err1 := util.ParseDuration(route.HealthCheck.Timeout)
				if err1 != nil {
					logger.Error("Health check timeout is invalid", "timeout", route.HealthCheck.Timeout)
				}
				timeout = d1
			}
			if len(route.Backends) != 0 {
				for index, backend := range route.Backends {
					health := Health{
						Name:               fmt.Sprintf("%s - [%d]", route.Name, index),
						URL:                backend.Endpoint + route.HealthCheck.Path,
						TimeOut:            timeout,
						Interval:           route.HealthCheck.Interval,
						HealthyStatuses:    route.HealthCheck.HealthyStatuses,
						InsecureSkipVerify: route.Security.TLS.SkipVerification,
					}
					healthRoutes = append(healthRoutes, health)
				}

			} else {
				health := Health{
					Name:               route.Name,
					URL:                route.Target + route.HealthCheck.Path,
					TimeOut:            timeout,
					Interval:           route.HealthCheck.Interval,
					HealthyStatuses:    route.HealthCheck.HealthyStatuses,
					InsecureSkipVerify: route.Security.TLS.SkipVerification,
				}
				healthRoutes = append(healthRoutes, health)
			}
		}
	}
	return healthRoutes
}
