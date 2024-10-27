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
	"io"
	"net/http"
	"net/url"
)

type HealthCheckRoute struct {
	DisableRouteHealthCheckError bool
	Routes                       []Route
}

// HealthCheckResponse represents the health check response structure
type HealthCheckResponse struct {
	Status string                     `json:"status"`
	Routes []HealthCheckRouteResponse `json:"routes"`
}
type HealthCheckRouteResponse struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

func HealthCheck(healthURL string) error {
	healthCheckURL, err := url.Parse(healthURL)
	if err != nil {
		return fmt.Errorf("error parsing HealthCheck URL: %v ", err)
	}
	// Create a new request for the route
	healthReq, err := http.NewRequest("GET", healthCheckURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating HealthCheck request: %v ", err)
	}
	// Perform the request to the route's healthcheck
	client := &http.Client{}
	healthResp, err := client.Do(healthReq)
	if err != nil {
		return fmt.Errorf("error performing HealthCheck request: %v ", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(healthResp.Body)

	if healthResp.StatusCode >= 400 {
		return fmt.Errorf("health check failed with status code %v", healthResp.StatusCode)
	}
	return nil
}
