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
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// ProxyHandler proxies incoming HTTP requests to the appropriate backend based on the configuration.
// It handles method validation, CORS headers, backend selection, and request rewriting.
func (proxyRoute ProxyRoute) ProxyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Log the start of the request with detailed context
		logger.Debug("Request started: method=%s, path=%s, client_ip=%s, user_agent=%s", r.Method, r.URL.Path, getRealIP(r), r.UserAgent())
		// Extract the Content-Type header from the request
		contentType := r.Header.Get("Content-Type")

		// Validate if the HTTP method is allowed
		if len(proxyRoute.methods) > 0 {
			if !slices.Contains(proxyRoute.methods, r.Method) {
				logger.Error("Method not allowed: method=%s, allowed_methods=%v", r.Method, proxyRoute.methods)
				middlewares.RespondWithError(w, r, http.StatusMethodNotAllowed, fmt.Sprintf("%d %s method is not allowed", http.StatusMethodNotAllowed, r.Method), proxyRoute.cors.Origins, contentType)
				return
			}
		}

		// Set CORS headers from the CORS configuration
		for k, v := range proxyRoute.cors.Headers {
			w.Header().Set(k, v)
		}

		// Handle CORS for allowed origins
		if allowedOrigin(proxyRoute.cors.Origins, r.Header.Get("Origin")) {
			logger.Debug("Handling preflight request for origin=%s", r.Header.Get("Origin"))
			// Handle preflight requests (OPTIONS)
			if r.Method == "OPTIONS" {
				w.Header().Set(accessControlAllowOrigin, r.Header.Get("Origin"))
				w.WriteHeader(http.StatusNoContent)
				return
			} else {
				w.Header().Set(accessControlAllowOrigin, r.Header.Get("Origin"))
			}
		}

		// Parse the target backend URL
		targetURL, err := url.Parse(proxyRoute.destination)
		if err != nil {
			logger.Error("Error parsing backend URL: %s", err)
			middlewares.RespondWithError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), nil, contentType)
			return
		}

		// Set headers for forwarding client information
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Header.Set("X-Forwarded-For", getRealIP(r))
		r.Header.Set("X-Real-IP", getRealIP(r))

		// Update the headers to allow for SSL redirection if host forwarding is disabled
		if proxyRoute.disableHostForwarding {
			r.URL.Scheme = targetURL.Scheme
			r.Host = targetURL.Host
			logger.Debug("Host forwarding disabled: updated request URL to scheme=%s, host=%s", targetURL.Scheme, targetURL.Host)
		}

		// Parse the backend URL for the reverse proxy
		backendURL, _ := url.Parse(proxyRoute.destination)
		proxy := httputil.NewSingleHostReverseProxy(backendURL)

		// If multiple backends are configured, use the appropriate load balancing algorithm
		if len(proxyRoute.backends) > 0 {
			if proxyRoute.weightedBased {
				// Use weighted-based load balancing
				proxy, err = NewWeightedReverseProxy(proxyRoute)
				if err != nil {
					logger.Error("Failed to create weighted reverse proxy: route=%s, error=%v", proxyRoute.name, err)
					middlewares.RespondWithError(w, r, http.StatusServiceUnavailable, fmt.Sprintf("%d service unavailable", http.StatusServiceUnavailable), proxyRoute.cors.Origins, contentType)
					return
				}
				logger.Debug("Proxy: using weighted-based load balancing")
			} else {
				// Use round-robin load balancing
				proxy, err = NewRoundRobinReverseProxy(proxyRoute)
				if err != nil {
					logger.Error("Failed to create round-robin reverse proxy: route=%s, error=%v", proxyRoute.name, err)
					middlewares.RespondWithError(w, r, http.StatusServiceUnavailable, fmt.Sprintf("%d service unavailable", http.StatusServiceUnavailable), proxyRoute.cors.Origins, contentType)
					return
				}
				logger.Debug("Using round-robin load balancing for route=%s", proxyRoute.name)
			}
		}

		// Rewrite the request path if necessary
		rewritePath(r, proxyRoute)
		// Configure the proxy transport to allow insecure SSL verification if enabled
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: proxyRoute.insecureSkipVerify,
			},
		}

		// Set a custom header to indicate the request is proxied
		w.Header().Set("Proxied-By", gatewayName)

		// Set a custom error handler for proxy errors
		proxy.ErrorHandler = ProxyErrorHandler

		// Forward the request to the selected backend
		proxy.ServeHTTP(w, r)
	}
}

// getNextBackend selects the next backend in a round-robin fashion.
func getNextBackend(backendURLs []string) *url.URL {
	idx := atomic.AddUint32(&counter, 1) % uint32(len(backendURLs))
	backendURL, _ := url.Parse(backendURLs[idx])
	return backendURL
}

// rewritePath rewrites the request path if it matches the configured prefix.
func rewritePath(r *http.Request, proxyRoute ProxyRoute) {
	if proxyRoute.path != "" && proxyRoute.rewrite != "" {
		// Rewrite the path if it matches the prefix
		if strings.HasPrefix(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path)) {
			r.URL.Path = util.ParseURLPath(strings.Replace(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path), proxyRoute.rewrite, 1))
		}
	}
}

// NewWeightedReverseProxy creates a reverse proxy that uses a weighted load balancing algorithm.
func NewWeightedReverseProxy(proxyRoute ProxyRoute) (*httputil.ReverseProxy, error) {
	// Check if there are any available backends
	availableBackend := proxyRoute.backends.AvailableBackend()
	if availableBackend == nil || len(availableBackend) == 0 {
		logger.Error("No available backends for route=%s", proxyRoute.name)
		return nil, fmt.Errorf("no available backends for route=%s", proxyRoute.name)
	}

	// Define the director function to select a backend based on weights
	director := func(req *http.Request) {
		backend := proxyRoute.backends.SelectBackend()
		if backend == nil {
			logger.Error("No available backends for route=%s", proxyRoute.name)
			return
		}

		// Parse the backend URL and update the request
		backendURL, err := url.Parse(backend.EndPoint)
		if err != nil {
			logger.Error("Error parsing backend URL for route %s: %v", proxyRoute.name, err)
			return
		}

		req.URL.Scheme = backendURL.Scheme
		req.URL.Host = backendURL.Host
		req.URL.Path = backendURL.Path + req.URL.Path
		req.Host = backendURL.Host
	}

	return &httputil.ReverseProxy{Director: director}, nil
}

// NewRoundRobinReverseProxy creates a reverse proxy that uses a round-robin load balancing algorithm.
func NewRoundRobinReverseProxy(proxyRoute ProxyRoute) (*httputil.ReverseProxy, error) {
	// Check if there are any available backends
	availableBackend := proxyRoute.backends.AvailableBackend()
	if availableBackend == nil || len(availableBackend) == 0 {
		logger.Error("No available backends for route=%s", proxyRoute.name)
		return nil, fmt.Errorf("no available backends for route=%s", proxyRoute.name)
	}

	// Define the director function to select the next backend in a round-robin fashion
	director := func(req *http.Request) {
		index := atomic.AddUint32(&counter, 1) % uint32(len(availableBackend))
		backend := proxyRoute.backends[index]

		// Parse the backend URL and update the request
		backendURL, _ := url.Parse(backend.EndPoint)
		req.URL.Scheme = backendURL.Scheme
		req.URL.Host = backendURL.Host
		req.URL.Path = backendURL.Path + req.URL.Path
		req.Host = backendURL.Host
		logger.Debug("Selected backend for route=%s: index=%d, endpoint=%s", proxyRoute.name, index, backend.EndPoint)
	}

	return &httputil.ReverseProxy{Director: director}, nil
}

// TotalWeight calculates the total weight of all backends.
func (b Backends) TotalWeight() int {
	total := 0
	for _, backend := range b {
		total += backend.Weight
	}
	return total
}

// SelectBackend selects a backend based on weighted randomization.
func (b Backends) SelectBackend() *Backend {
	rand.Seed(time.Now().UnixNano())
	r := rand.Intn(b.TotalWeight())
	for _, backend := range b {
		r -= backend.Weight
		if r < 0 {
			return &backend
		}
	}
	return nil
}

// HasPositiveWeight checks if at least one backend has a positive weight.
func (b Backends) HasPositiveWeight() bool {
	for _, backend := range b {
		if backend.Weight > 0 {
			return true
		}
	}
	logger.Debug("No backend with positive weight found")
	return false
}

// AvailableBackend returns a list of backends that are not marked as unavailable.
func (b Backends) AvailableBackend() Backends {
	backends := Backends{}
	for _, backend := range b {
		if !backend.unavailable {
			backends = append(backends, backend)
		}
	}
	logger.Debug("Available backends: count=%d", len(backends))
	return backends
}
