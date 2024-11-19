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
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/robfig/cron/v3"
	"io"
	"net/http"
	"net/url"
	"slices"
)

func (health Health) Check() error {
	healthCheckURL, err := url.Parse(health.URL)
	if err != nil {
		return fmt.Errorf("error parsing HealthCheck URL: %v ", err)
	}
	// Create a new request for the route
	healthReq, err := http.NewRequest("GET", healthCheckURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error route %s: creating HealthCheck request: %v ", health.Name, err)
	}
	// Create custom transport with TLS configuration
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: health.InsecureSkipVerify, // Skip SSL certificate verification
		},
	}
	//Set user-agent
	healthReq.Header.Set("User-Agent", fmt.Sprintf("Goma-Gateway/%s", util.Version))
	// Perform the request to the route's healthcheck
	client := &http.Client{Transport: transport, Timeout: health.TimeOut}
	healthResp, err := client.Do(healthReq)
	if err != nil {
		logger.Debug("Error route %s: performing HealthCheck request: %v ", health.Name, err)
		return fmt.Errorf("error  performing HealthCheck request: %v ", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logger.Debug("Error performing HealthCheck request: %v ", err)
		}
	}(healthResp.Body)
	if len(health.HealthyStatuses) > 0 {
		if !slices.Contains(health.HealthyStatuses, healthResp.StatusCode) {
			logger.Debug("Error: Route %s: health check failed with status code %d", health.Name, healthResp.StatusCode)
			return fmt.Errorf("health check failed with status code %d", healthResp.StatusCode)
		}
	} else {
		if healthResp.StatusCode >= 400 {
			logger.Debug("Error: Route %s: health check failed with status code %d", health.Name, healthResp.StatusCode)
			return fmt.Errorf("health check failed with status code %d", healthResp.StatusCode)
		}
	}
	return nil
}
func routesHealthCheck(routes []Route) {
	for _, health := range healthCheckRoutes(routes) {
		go func() {
			err := health.createHealthCheckJob()
			if err != nil {
				logger.Error("Error creating healthcheck job: %v ", err)
				return
			}

		}()

	}
}
func (health Health) createHealthCheckJob() error {
	interval := "30s"
	if len(health.Interval) > 0 {
		interval = health.Interval
	}
	expression := fmt.Sprintf("@every %s", interval)
	if !util.IsValidCronExpression(expression) {
		logger.Error("Health check interval is invalid: %s", interval)
		logger.Info("Route health check ignored")
		return fmt.Errorf("health check interval is invalid: %s", interval)
	}
	// Create a new cron instance
	c := cron.New()
	_, err := c.AddFunc(expression, func() {
		err := health.Check()
		if err != nil {
			logger.Error("Route %s is unhealthy: %v", health.Name, err.Error())
			return
		}
		logger.Info("Route %s is healthy", health.Name)
	})
	if err != nil {
		return err
	}
	// Start the cron scheduler
	c.Start()
	defer c.Stop()
	select {}
}
