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
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
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

// ProxyHandler is the main handler for proxying incoming HTTP requests.
// It handles method validation, CORS headers, backend selection, and request rewriting.
func (proxyRoute *ProxyRoute) ProxyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the Content-Type header from the request
		contentType := r.Header.Get("Content-Type")

		// Validate if the HTTP method is allowed
		if !proxyRoute.validateMethod(r.Method, w, r, contentType) {
			return
		}

		// Set CORS headers from the CORS configuration
		proxyRoute.applyCORSHeaders(w)

		// Handle preflight requests (OPTIONS) for CORS
		if proxyRoute.handlePreflight(w, r) {
			return
		}

		// Set headers for forwarding client information
		proxyRoute.forwardedHeaders(r)

		// Create a reverse proxy based on the configuration
		proxy, err := proxyRoute.createProxy(r, contentType, w)
		if err != nil {
			return
		}

		// Rewrite the request path if necessary
		proxyRoute.rewritePath(r)

		// Configure the proxy transport to allow insecure SSL verification if enabled
		proxy.Transport = proxyRoute.createProxyTransport()

		// Set a custom header to indicate the request is proxied
		w.Header().Set("Proxied-By", util.GatewayName)

		// Set a custom error handler for proxy errors
		proxy.ErrorHandler = ProxyErrorHandler

		// Forward the request to the selected backend
		proxy.ServeHTTP(w, r)
	}
}

// validateMethod checks if the HTTP method is allowed for the request.
// Returns false and sends an error response if the method is not allowed.
func (proxyRoute *ProxyRoute) validateMethod(method string, w http.ResponseWriter, r *http.Request, contentType string) bool {
	if len(proxyRoute.methods) > 0 && !slices.Contains(proxyRoute.methods, method) {
		logger.Warn("Method not allowed", "method", method, "allowed_methods", proxyRoute.methods)
		middlewares.RespondWithError(w, r, http.StatusMethodNotAllowed, fmt.Sprintf("%d %s method is not allowed", http.StatusMethodNotAllowed, method), proxyRoute.cors.Origins, contentType)
		return false
	}
	return true
}

// applyCORSHeaders sets the CORS headers from the provided configuration.
func (proxyRoute *ProxyRoute) applyCORSHeaders(w http.ResponseWriter) {
	for k, v := range proxyRoute.cors.Headers {
		w.Header().Set(k, v)
	}
}

// handlePreflight handles preflight requests (OPTIONS) for CORS.
// Returns true if the request is a preflight request and has been handled.
func (proxyRoute *ProxyRoute) handlePreflight(w http.ResponseWriter, r *http.Request) bool {
	if allowedOrigin(proxyRoute.cors.Origins, r.Header.Get("Origin")) {
		logger.Debug("Handling preflight request,", "origin", r.Header.Get("Origin"))
		w.Header().Set(accessControlAllowOrigin, r.Header.Get("Origin"))
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return true
		}
	}
	return false
}

// forwardedHeaders sets headers for forwarding client information.
func (proxyRoute *ProxyRoute) forwardedHeaders(r *http.Request) {
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-For", getRealIP(r))
	r.Header.Set("X-Real-IP", getRealIP(r))
	r.Header.Set("X-Forwarded-Proto", scheme(r))
}

// createProxy creates a reverse proxy based on the configuration.
// It selects between single-host, weighted, or round-robin load balancing.
func (proxyRoute *ProxyRoute) createProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	if len(proxyRoute.backends) == 0 {
		return proxyRoute.createSingleHostProxy(r, contentType, w)
	}
	if proxyRoute.weightedBased {
		return proxyRoute.createWeightedProxy(r, contentType, w)
	}
	return proxyRoute.createRoundRobinProxy(r, contentType, w)
}

// createSingleHostProxy creates a reverse proxy for a single backend.
func (proxyRoute *ProxyRoute) createSingleHostProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	backendURL, err := url.Parse(proxyRoute.target)
	if err != nil {
		logger.Error("Error parsing backend URL", "error", err)
		middlewares.RespondWithError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), nil, contentType)
		return nil, err
	}

	// Update the headers to allow for SSL redirection if host forwarding is disabled
	if !proxyRoute.security.ForwardHostHeaders {
		logger.Debug(">>> Forwarding host headers disabled")
		r.URL.Scheme = backendURL.Scheme
		r.Host = backendURL.Host
	}
	return httputil.NewSingleHostReverseProxy(backendURL), nil
}

// createWeightedProxy creates a reverse proxy using weighted load balancing.
func (proxyRoute *ProxyRoute) createWeightedProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	proxy, err := proxyRoute.NewWeightedReverseProxy(r)
	if err != nil {
		logger.Error("Failed to create weighted reverse proxy", "route", proxyRoute.name, "error", err)
		middlewares.RespondWithError(w, r, http.StatusServiceUnavailable, fmt.Sprintf("%d service unavailable", http.StatusServiceUnavailable), proxyRoute.cors.Origins, contentType)
	}
	return proxy, err
}

// createRoundRobinProxy creates a reverse proxy using round-robin load balancing.
func (proxyRoute *ProxyRoute) createRoundRobinProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	proxy, err := proxyRoute.NewRoundRobinReverseProxy(r)
	if err != nil {
		logger.Error("Failed to create round-robin reverse proxy", "route", proxyRoute.name, "error", err)
		middlewares.RespondWithError(w, r, http.StatusServiceUnavailable, fmt.Sprintf("%d service unavailable", http.StatusServiceUnavailable), proxyRoute.cors.Origins, contentType)
	}
	return proxy, err
}

// createProxyTransport creates custom transport for the reverse proxy.
// It allows insecure SSL verification if enabled in the configuration.
func (proxyRoute *ProxyRoute) createProxyTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: proxyRoute.security.TLS.SkipVerification,
			RootCAs:            proxyRoute.certPool,
		},
	}
}

// rewritePath rewrites the request path if it matches the configured prefix.
func (proxyRoute *ProxyRoute) rewritePath(r *http.Request) {
	if proxyRoute.path != "" && proxyRoute.rewrite != "" {
		// Rewrite the path if it matches the prefix
		if strings.HasPrefix(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path)) {
			r.URL.Path = util.ParseURLPath(strings.Replace(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path), proxyRoute.rewrite, 1))
		}
	}
}

// NewWeightedReverseProxy creates a reverse proxy that uses a weighted load balancing algorithm.
func (proxyRoute *ProxyRoute) NewWeightedReverseProxy(r *http.Request) (*httputil.ReverseProxy, error) {
	// Check if there are any available backends
	availableBackend := proxyRoute.backends.AvailableBackend()
	if len(availableBackend) == 0 {
		logger.Error("No available backends", "route", proxyRoute.name)
		return nil, fmt.Errorf("no available backends for route=%s", proxyRoute.name)
	}

	backend := proxyRoute.backends.SelectBackend()
	if backend == nil {
		return nil, fmt.Errorf("no available backends for route=%s", proxyRoute.name)
	}

	// Save backend in context
	r = r.WithContext(context.WithValue(r.Context(), CtxSelectedBackend, backend))

	// Parse the backend URL and update the request
	backendURL, err := url.Parse(backend.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("error parsing backend URL for route %s: %v", proxyRoute.name, err)
	}
	if !proxyRoute.security.ForwardHostHeaders {
		logger.Debug(">>> Forwarding host headers")
		r.URL.Scheme = backendURL.Scheme
		r.Host = backendURL.Host
	}
	return httputil.NewSingleHostReverseProxy(backendURL), nil
}

// NewRoundRobinReverseProxy creates a reverse proxy that uses a round-robin load balancing algorithm.
func (proxyRoute *ProxyRoute) NewRoundRobinReverseProxy(r *http.Request) (*httputil.ReverseProxy, error) {
	// Check if there are any available backends
	availableBackend := proxyRoute.backends.AvailableBackend()
	if len(availableBackend) == 0 {
		logger.Error("No available backends", "route", proxyRoute.name)
		return nil, fmt.Errorf("no available backends for route=%s", proxyRoute.name)
	}

	index := atomic.AddUint32(&counter, 1) % uint32(len(availableBackend))
	backend := proxyRoute.backends[index]

	// Save backend in context
	r = r.WithContext(context.WithValue(r.Context(), CtxSelectedBackend, backend))

	// Parse the backend URL and update the request
	backendURL, _ := url.Parse(backend.Endpoint)
	if !proxyRoute.security.ForwardHostHeaders {
		logger.Debug(">>> Forwarding host headers")
		r.URL.Scheme = backendURL.Scheme
		r.Host = backendURL.Host
	}
	return httputil.NewSingleHostReverseProxy(backendURL), nil
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
	// Create a new local random number generator with a time-based seed
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Generate a random number between 0 and the total weight
	r := rng.Intn(b.TotalWeight())

	// Iterate through the backends and select one based on the random number
	for _, backend := range b {
		r -= backend.Weight
		if r < 0 {
			return &backend
		}
	}

	// Return nil if no backend is selected (should not happen if weights are valid)
	return nil
}

// HasPositiveWeight checks if at least one backend has a positive weight.
func (b Backends) HasPositiveWeight() bool {
	for _, backend := range b {
		if backend.Weight > 0 {
			return true
		}
	}
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
	return backends
}
