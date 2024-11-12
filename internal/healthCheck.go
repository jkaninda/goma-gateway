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
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/robfig/cron/v3"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

type Health struct {
	URL             string
	TimeOut         time.Duration
	HealthyStatuses []int
}

func (health Health) Check() error {
	healthCheckURL, err := url.Parse(health.URL)
	if err != nil {
		return fmt.Errorf("error parsing HealthCheck URL: %v ", err)
	}
	// Create a new request for the route
	healthReq, err := http.NewRequest("GET", healthCheckURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating HealthCheck request: %v ", err)
	}
	// Perform the request to the route's healthcheck
	client := &http.Client{Timeout: health.TimeOut}
	healthResp, err := client.Do(healthReq)
	if err != nil {
		logger.Error("Error performing HealthCheck request: %v ", err)
		return fmt.Errorf("error performing HealthCheck request: %v ", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
		}
	}(healthResp.Body)
	if len(health.HealthyStatuses) > 0 {
		if !slices.Contains(health.HealthyStatuses, healthResp.StatusCode) {
			logger.Error("Error: health check failed with status code %d", healthResp.StatusCode)
			return fmt.Errorf("health check failed with status code %v", healthResp.StatusCode)
		}
	} else {
		if healthResp.StatusCode >= 400 {
			logger.Error("Error: health check failed with status code %d", healthResp.StatusCode)
			return fmt.Errorf("health check failed with status code %v", healthResp.StatusCode)
		}
	}
	return nil
}
func routesHealthCheck(routes []Route) {
	for _, route := range routes {
		go func() {
			if len(route.HealthCheck.Path) > 0 {
				interval := "30s"
				timeout, _ := util.ParseDuration("")
				if len(route.HealthCheck.Interval) > 0 {
					interval = route.HealthCheck.Interval
				}
				expression := fmt.Sprintf("@every %s", interval)
				if !util.IsValidCronExpression(expression) {
					logger.Error("Health check interval is invalid: %s", interval)
					logger.Info("Route health check ignored")
					return
				}
				if len(route.HealthCheck.Timeout) > 0 {
					d1, err1 := util.ParseDuration(route.HealthCheck.Timeout)
					if err1 != nil {
						logger.Error("Health check timeout is invalid: %s", route.HealthCheck.Timeout)
						return
					}
					timeout = d1

				}
				if len(route.Backends) > 0 {
					for index, backend := range route.Backends {
						err := createCron(fmt.Sprintf("%s [%d]", route.Name, index), expression, backend+route.HealthCheck.Path, timeout, route.HealthCheck.HealthyStatuses)
						if err != nil {
							logger.Error("Error creating cron expression: %v ", err)
							return
						}
					}

				} else {
					err := createCron(route.Name, expression, route.Destination+route.HealthCheck.Path, timeout, route.HealthCheck.HealthyStatuses)
					if err != nil {
						logger.Error("Error creating cron expression: %v ", err)
						return
					}
				}

			}
		}()

	}
}
func createCron(name, expression string, healthURL string, timeout time.Duration, healthyStatuses []int) error {
	// Create a new cron instance
	c := cron.New()

	_, err := c.AddFunc(expression, func() {
		health := Health{
			URL:             healthURL,
			TimeOut:         timeout,
			HealthyStatuses: healthyStatuses,
		}
		err := health.Check()
		if err != nil {
			logger.Error("Route %s is unhealthy: error %v", name, err.Error())
			return
		}
		logger.Info("Route %s is healthy", name)
	})
	if err != nil {
		return err
	}
	// Start the cron scheduler
	c.Start()
	defer c.Stop()
	select {}
}

type HealthCheck struct {
	url             string
	interval        string
	timeout         string
	healthyStatuses []int
}
