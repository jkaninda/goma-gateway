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
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/util"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// ProxyHandler is the main handler for proxying incoming HTTP requests.
// It handles method validation, CORS headers, backend selection, and request rewriting.
func (pr *ProxyRoute) ProxyHandler() http.HandlerFunc {
	transport := pr.createProxyTransport()

	return func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		origin := r.Header.Get("Origin")

		// Validate if the HTTP method is allowed
		if !pr.validateMethod(r.Method, w, r, contentType) {
			return
		}
		// Check if CORS is enabled for this route
		if pr.cors.Enabled && pr.allowedOrigin(origin) {
			// Set CORS headers from the CORS configuration
			pr.applyCORSHeaders(w)

			// Handle preflight requests (OPTIONS) for CORS only if the origins are defined
			if len(pr.cors.Origins) > 0 && origin != "" {
				if pr.handlePreflight(w, r, origin) {
					return
				}
			}
		}

		// Set headers for forwarding client information
		pr.forwardedHeaders(r)

		// Create a reverse proxy based on the configuration
		proxy, err := pr.createProxy(r, contentType, w)
		if err != nil {
			return
		}

		// Rewrite the request path if necessary
		pr.rewritePath(r)

		proxy.Transport = transport

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
func (pr *ProxyRoute) validateMethod(method string, w http.ResponseWriter, r *http.Request, contentType string) bool {
	if len(pr.methods) > 0 && !slices.Contains(pr.methods, method) {
		logger.Warn("Method not allowed", "method", method, "allowed_methods", pr.methods)
		middlewares.RespondWithError(w, r, http.StatusMethodNotAllowed,
			"405 "+method+" method not allowed", pr.cors.Origins, contentType)
		return false
	}
	return true
}

// applyCORSHeaders sets the CORS headers from the provided configuration.
func (pr *ProxyRoute) applyCORSHeaders(w http.ResponseWriter) {
	for k, v := range pr.cors.Headers {
		w.Header().Set(k, v)
	}
}

// handlePreflight handles preflight requests (OPTIONS) for CORS.
// Returns true if the request is a preflight request and has been handled.
func (pr *ProxyRoute) handlePreflight(w http.ResponseWriter, r *http.Request, origin string) bool {
	logger.Debug("Handling preflight request,", "origin", origin)
	w.Header().Set(accessControlAllowOrigin, origin)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}

	return false
}
func (pr *ProxyRoute) allowedOrigin(origin string) bool {
	if len(pr.cors.Origins) == 0 || origin == "" {
		return true // Allow all origins if none specified
	}
	for _, o := range pr.cors.Origins {
		if o == "*" || o == origin {
			return true // Match found
		}
	}
	return false // No match found
}

// forwardedHeaders sets headers for forwarding client information.
func (pr *ProxyRoute) forwardedHeaders(r *http.Request) {
	realIP := getRealIP(r)
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-For", realIP)
	r.Header.Set("X-Real-IP", realIP)
	r.Header.Set("X-Forwarded-Proto", scheme(r))
}

// createProxy creates a reverse proxy based on the configuration.
// It selects between single-host, weighted, or round-robin load balancing.
func (pr *ProxyRoute) createProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	logger.Debug("Creating proxy", "route", pr.name, "method", r.Method, "path", r.URL.Path, "contentType", contentType)
	if len(pr.backends) == 0 || len(pr.backends) == 1 {
		if len(pr.backends) == 1 {
			pr.target = pr.backends[0].Endpoint
			logger.Debug("Using single backend proxy", "backends", len(pr.backends))
		}
		logger.Debug("Using  single backend proxy ", "target", pr.target)
		return pr.createSingleHostProxy(r, contentType, w)
	}
	if pr.canaryBased {
		return pr.createCanaryProxy(r, contentType, w)
	}
	if pr.weightedBased {
		logger.Debug("Using weighted load balancing strategy", "backends", len(pr.backends))
		return pr.createWeightedProxy(r, contentType, w)
	}
	logger.Debug("Using round-robin load balancing strategy", "backends", len(pr.backends))
	return pr.createRoundRobinProxy(r, contentType, w)
}

// createSingleHostProxy creates a reverse proxy for a single backend.
func (pr *ProxyRoute) createSingleHostProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	backendURL, err := url.Parse(pr.target)
	if err != nil {
		logger.Error("Error parsing backend URL", "error", err)
		middlewares.RespondWithError(w, r, http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError), nil, contentType)
		return nil, err
	}
	// Update the headers to allow for SSL redirection if host forwarding is disabled
	if !pr.security.ForwardHostHeaders {
		logger.Debug(">>> Forwarding host headers disabled")
		r.URL.Scheme = backendURL.Scheme
		r.Host = backendURL.Host
	}
	return httputil.NewSingleHostReverseProxy(backendURL), nil
}

// createWeightedProxy creates a reverse proxy using weighted load balancing.
func (pr *ProxyRoute) createWeightedProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	proxy, backendURL, err := pr.NewWeightedReverseProxy(r)
	if err != nil {
		logger.Error("Failed to create weighted reverse proxy", "route", pr.name, "error", err)
		middlewares.RespondWithError(w, r, http.StatusServiceUnavailable,
			"503 service unavailable", pr.cors.Origins, contentType)
	}
	// Update the headers to allow for SSL redirection if host forwarding is disabled
	if !pr.security.ForwardHostHeaders {
		logger.Debug(">>> Forwarding host headers disabled")
		r.URL.Scheme = backendURL.Scheme
		r.Host = backendURL.Host
	}
	return proxy, err
}

// createRoundRobinProxy creates a reverse proxy using round-robin load balancing.
func (pr *ProxyRoute) createRoundRobinProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	proxy, backendURL, err := pr.NewRoundRobinReverseProxy(r)
	if err != nil {
		logger.Error("Failed to create round-robin reverse proxy", "route", pr.name, "error", err)
		middlewares.RespondWithError(w, r, http.StatusServiceUnavailable,
			"503 service unavailable", pr.cors.Origins, contentType)
	}
	// Update the headers to allow for SSL redirection if host forwarding is disabled
	if !pr.security.ForwardHostHeaders {
		logger.Debug(">>> Forwarding host headers disabled")
		r.URL.Scheme = backendURL.Scheme
		r.Host = backendURL.Host
	}
	// Save backend in context
	// r.WithContext(context.WithValue(r.Context(), CtxSelectedBackend, backendURL.Hostname()))
	return proxy, err
}

// createProxyTransport creates custom transport for the reverse proxy.
// It allows insecure SSL verification if enabled in the configuration.
func (pr *ProxyRoute) createProxyTransport() *http.Transport {
	logger.Debug("Creating proxy transport",
		"route", pr.name, "target", pr.target,
		"DisableCompression", pr.networking.Transport.DisableCompression,
		"MaxIdleConns", pr.networking.Transport.MaxIdleConns,
		"MaxIdleConnsPerHost", pr.networking.Transport.MaxIdleConnsPerHost,
		"IdleConnTimeout", pr.networking.Transport.IdleConnTimeout,
		"ForceAttemptHTTP2", pr.networking.Transport.ForceAttemptHTTP2)
	return &http.Transport{
		DisableCompression:    pr.networking.Transport.DisableCompression,
		MaxIdleConns:          pr.networking.Transport.MaxIdleConns,
		MaxIdleConnsPerHost:   pr.networking.Transport.MaxIdleConnsPerHost,
		MaxConnsPerHost:       pr.networking.Transport.MaxConnsPerHost,
		TLSHandshakeTimeout:   time.Duration(pr.networking.Transport.TLSHandshakeTimeout) * time.Second,
		ResponseHeaderTimeout: time.Duration(pr.networking.Transport.ResponseHeaderTimeout) * time.Second,
		IdleConnTimeout:       time.Duration(pr.networking.Transport.IdleConnTimeout) * time.Second,
		DialContext:           cachedDialer.DialContext,
		ForceAttemptHTTP2:     pr.networking.Transport.ForceAttemptHTTP2,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: pr.security.TLS.InsecureSkipVerify,
			RootCAs:            pr.certPool,
		},
	}
}

// rewritePath rewrites the request path if it matches the configured prefix.
func (pr *ProxyRoute) rewritePath(r *http.Request) {
	if pr.path != "" && pr.rewrite != "" {
		pathPrefix := pr.path + "/"
		if strings.HasPrefix(r.URL.Path, pathPrefix) {
			logger.Debug(">>> Rewriting path", "route", pr.name, "current_path", r.URL.Path, "path", pr.path, "rewrite", pr.rewrite)
			newPath := pr.rewrite + "/" + r.URL.Path[len(pathPrefix):]
			r.URL.Path = util.ParseURLPath(newPath)
			logger.Debug(">>> Rewrote path", "route", pr.name, "path", pr.path, "rewrite", pr.rewrite, "new_path", r.URL.Path)
		}
	}
}

// NewWeightedReverseProxy creates a reverse proxy that uses a weighted load balancing algorithm.
func (pr *ProxyRoute) NewWeightedReverseProxy(r *http.Request) (*httputil.ReverseProxy, *url.URL, error) {
	if !pr.backends.hasAvailableBackends() {
		logger.Error("No available backends", "route", pr.name)
		return nil, nil, fmt.Errorf("no available backends for route=%s", pr.name)
	}

	backend := pr.backends.SelectBackend()
	if backend == nil {
		return nil, nil, fmt.Errorf("no available backends for route=%s", pr.name)
	}

	// Parse the backend URL and update the request
	backendURL, err := url.Parse(backend.Endpoint)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing backend URL for route %s: %v", pr.name, err)
	}
	return httputil.NewSingleHostReverseProxy(backendURL), backendURL, nil
}

// NewRoundRobinReverseProxy creates a reverse proxy that uses a round-robin load balancing algorithm.
func (pr *ProxyRoute) NewRoundRobinReverseProxy(r *http.Request) (*httputil.ReverseProxy, *url.URL, error) {
	availableCount := pr.backends.availableBackendCount()
	if availableCount == 0 {
		logger.Error("No available backends", "route", pr.name)
		return nil, nil, fmt.Errorf("no available backends for route=%s", pr.name)
	}

	// Find the next available backend using round-robin
	backend := pr.backends.getNextAvailableBackend(availableCount)
	if backend == nil {
		return nil, nil, fmt.Errorf("no available backends for route=%s", pr.name)
	}

	// Parse the backend URL and update the request
	backendURL, _ := url.Parse(backend.Endpoint)

	return httputil.NewSingleHostReverseProxy(backendURL), backendURL, nil
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
	totalWeight := b.TotalWeight()
	if totalWeight == 0 {
		return nil
	}

	r := rand.Intn(totalWeight)

	// Iterate through the backends and select one based on the random number
	for i := range b {
		if b[i].unavailable {
			continue
		}
		r -= b[i].Weight
		if r < 0 {
			return &b[i]
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
func (b Backends) IsCanaryBased() bool {
	for _, backend := range b {
		if len(backend.Match) > 0 {
			return true
		}
	}
	return false
}

// hasAvailableBackends checks if there are any available backends without creating a new slice.
func (b Backends) hasAvailableBackends() bool {
	for _, backend := range b {
		if !backend.unavailable {
			return true
		}
	}
	return false
}

// availableBackendCount returns the count of available backends.
func (b Backends) availableBackendCount() int {
	count := 0
	for _, backend := range b {
		if !backend.unavailable {
			count++
		}
	}
	return count
}

// getNextAvailableBackend returns the next available backend using round-robin.
func (b Backends) getNextAvailableBackend(availableCount int) *Backend {
	if availableCount == 0 {
		return nil
	}

	index := atomic.AddUint32(&counter, 1) % uint32(availableCount)
	currentIndex := uint32(0)

	for i := range b {
		if !b[i].unavailable {
			if currentIndex == index {
				return &b[i]
			}
			currentIndex++
		}
	}

	return nil
}

// createCanaryProxy creates a reverse proxy using canary deployment logic.
func (pr *ProxyRoute) createCanaryProxy(r *http.Request, contentType string, w http.ResponseWriter) (*httputil.ReverseProxy, error) {
	if !pr.backends.hasAvailableBackends() {
		logger.Error("No available backends", "route", pr.name)
		middlewares.RespondWithError(w, r, http.StatusServiceUnavailable,
			"503 service unavailable", pr.cors.Origins, contentType)
		return nil, fmt.Errorf("no available backends for route=%s", pr.name)
	}

	backend := pr.backends.SelectCanaryBackend(r)
	if backend == nil {
		backend = pr.backends.SelectStableBackend()
		if backend == nil {
			logger.Error("No available stable backends", "route", pr.name)
			middlewares.RespondWithError(w, r, http.StatusServiceUnavailable,
				"503 service unavailable", pr.cors.Origins, contentType)
			return nil, fmt.Errorf("no available stable backends for route=%s", pr.name)
		}
	}
	// Parse the backend URL and update the request
	backendURL, err := url.Parse(backend.Endpoint)
	if err != nil {
		logger.Error("Error parsing backend URL", "route", pr.name, "error", err)
		middlewares.RespondWithError(w, r, http.StatusInternalServerError,
			http.StatusText(http.StatusInternalServerError), pr.cors.Origins, contentType)
		return nil, err
	}

	// Update the headers to allow for SSL redirection if host forwarding is disabled
	if !pr.security.ForwardHostHeaders {
		logger.Debug(">>> Forwarding host headers disabled")
		r.URL.Scheme = backendURL.Scheme
		r.Host = backendURL.Host
	}

	logger.Debug("Selected backend for canary deployment",
		"route", pr.name,
		"backend", backend.Endpoint,
		"isCanary", len(backend.Match) > 0)

	return httputil.NewSingleHostReverseProxy(backendURL), nil
}

// SelectCanaryBackend selects a backend based on canary deployment rules.
func (b Backends) SelectCanaryBackend(r *http.Request) *Backend {
	// check for exclusive canary backends that match the request
	for i := range b {
		if b[i].unavailable {
			continue
		}

		// Check if this is a canary backend with matching rules
		if len(b[i].Match) > 0 {
			if b.matchesRequest(&b[i], r) {
				logger.Debug("Canary backend matched",
					"endpoint", b[i].Endpoint,
					"exclusive", b[i].Exclusive)

				// If it's an exclusive canary and matches, use it
				if b[i].Exclusive {
					return &b[i]
				}

				// TODO: Improve logic for non-exclusive canary
				return &b[i]
			}
		}
	}

	return nil
}

// SelectStableBackend selects a stable (non-canary) backend using weighted selection.
func (b Backends) SelectStableBackend() *Backend {
	var stableBackends []Backend

	// Collect all stable (non-canary) backends
	for i := range b {
		if b[i].unavailable {
			continue
		}

		if len(b[i].Match) == 0 {
			stableBackends = append(stableBackends, b[i])
		}
	}

	if len(stableBackends) == 0 {
		return nil
	}

	// Use weighted selection for stable backends
	return Backends(stableBackends).SelectBackend()
}

// matchesRequest checks if a backend's match rules are satisfied by the request.
func (b Backends) matchesRequest(backend *Backend, r *http.Request) bool {
	for _, match := range backend.Match {
		if !b.evaluateMatch(match, r) {
			return false
		}
	}
	return true
}

// evaluateMatch evaluates a single match rule against the request.
func (b Backends) evaluateMatch(match BackendMatch, r *http.Request) bool {
	var value string

	switch match.Source {
	case SourceTypeHeader:
		value = r.Header.Get(match.Name)
	case SourceTypeCookie:
		if cookie, err := r.Cookie(match.Name); err == nil {
			value = cookie.Value
		}
	case SourceTypeQuery:
		value = r.URL.Query().Get(match.Name)
	case SourceTypeIp:
		value = getRealIP(r)
	default:
		logger.Warn("Unknown source type for canary matching", "source", match.Source)
		return false
	}

	// Evaluate based on operator
	return b.evaluateOperator(match.Operator, value, match.Value)
}

func (b Backends) evaluateOperator(op OperatorType, actualValue, expectedValue string) bool {
	switch op {
	case OperatorEquals:
		return actualValue == expectedValue
	case OperatorNotEquals:
		return actualValue != expectedValue
	case OperatorContains:
		return strings.Contains(actualValue, expectedValue)
	case OperatorNotContains:
		return !strings.Contains(actualValue, expectedValue)
	case OperatorStartsWith:
		return strings.HasPrefix(actualValue, expectedValue)
	case OperatorEndsWith:
		return strings.HasSuffix(actualValue, expectedValue)
	case OperatorRegex:
		matched, err := regexp.MatchString(expectedValue, actualValue)
		if err != nil {
			logger.Error("Invalid regex pattern", "pattern", expectedValue, "error", err)
			return false
		}
		return matched
	case OperatorIn:
		values := strings.Split(expectedValue, ",")
		for _, v := range values {
			if strings.TrimSpace(v) == actualValue {
				return true
			}
		}
		return false
	default:
		logger.Warn("Unknown operator for canary matching", "operator", op)
		return false
	}
}
