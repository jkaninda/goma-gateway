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

// ProxyHandler proxies requests to the backend
func (proxyRoute ProxyRoute) ProxyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Debug("started %s %s for %s %s", r.Method, r.URL.Path, getRealIP(r), r.UserAgent())
		contentType := r.Header.Get("Content-Type")
		// Check Method if is allowed
		if len(proxyRoute.methods) > 0 {
			if !slices.Contains(proxyRoute.methods, r.Method) {
				logger.Error("%s Method is not allowed", r.Method)
				middlewares.RespondWithError(w, r, http.StatusMethodNotAllowed, fmt.Sprintf("%d %s method is not allowed", http.StatusMethodNotAllowed, r.Method), proxyRoute.cors.Origins, contentType)
				return
			}
		}
		// Set CORS headers from the cors config
		// Update Cors Headers
		for k, v := range proxyRoute.cors.Headers {
			w.Header().Set(k, v)
		}
		if allowedOrigin(proxyRoute.cors.Origins, r.Header.Get("Origin")) {
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
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Header.Set("X-Forwarded-For", getRealIP(r))
		r.Header.Set("X-Real-IP", getRealIP(r))
		// Update the headers to allow for SSL redirection
		if proxyRoute.disableHostForwarding {
			r.URL.Scheme = targetURL.Scheme
			r.Host = targetURL.Host
		}
		backendURL, _ := url.Parse(proxyRoute.destination)
		proxy := httputil.NewSingleHostReverseProxy(backendURL)

		if len(proxyRoute.backends) > 0 {
			if proxyRoute.weightedBased {
				// Reverse Proxy Weighted based algorithm
				proxy, err = NewWeightedReverseProxy(proxyRoute)
				if err != nil {
					middlewares.RespondWithError(w, r, http.StatusServiceUnavailable, fmt.Sprintf("%d service unaivalable", http.StatusServiceUnavailable), proxyRoute.cors.Origins, contentType)
					return
				}
				logger.Debug("Proxy: using Weighted algorithm")
			} else {
				// Reverse Proxy RoundRobin based algorithm
				proxy, err = NewRoundRobinReverseProxy(proxyRoute)
				if err != nil {
					middlewares.RespondWithError(w, r, http.StatusServiceUnavailable, fmt.Sprintf("%d service unaivalable", http.StatusServiceUnavailable), proxyRoute.cors.Origins, contentType)
					return
				}
				logger.Debug("Proxy: using RoundRobin algorithm")
			}
		}
		// Rewrite
		rewritePath(r, proxyRoute)
		// Custom transport with InsecureSkipVerify
		proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify: proxyRoute.insecureSkipVerify,
		},
		}
		w.Header().Set("Proxied-By", gatewayName)
		// Custom error handler for proxy errors
		proxy.ErrorHandler = ProxyErrorHandler
		proxy.ServeHTTP(w, r)
	}
}

// getNextBackend selects the next backend in a round-robin fashion
func getNextBackend(backendURLs []string) *url.URL {
	idx := atomic.AddUint32(&counter, 1) % uint32(len(backendURLs))
	backendURL, _ := url.Parse(backendURLs[idx])
	return backendURL
}

// rewritePath rewrites the path if it matches the prefix
func rewritePath(r *http.Request, proxyRoute ProxyRoute) {
	if proxyRoute.path != "" && proxyRoute.rewrite != "" {
		// Rewrite the path if it matches the prefix
		if strings.HasPrefix(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path)) {
			r.URL.Path = util.ParseURLPath(strings.Replace(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path), proxyRoute.rewrite, 1))
		}
	}
}
func NewWeightedReverseProxy(proxyRoute ProxyRoute) (*httputil.ReverseProxy, error) {
	availableBackend := proxyRoute.backends.AvailableBackend()
	if availableBackend == nil || len(availableBackend) == 0 {
		return nil, fmt.Errorf("route %s has no backends available", proxyRoute.name)
	}
	director := func(req *http.Request) {
		backend := proxyRoute.backends.SelectBackend()
		if backend == nil {
			logger.Error("Error, route %s has no backends available", proxyRoute.name)
			return
		}
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

func NewRoundRobinReverseProxy(proxyRoute ProxyRoute) (*httputil.ReverseProxy, error) {
	availableBackend := proxyRoute.backends.AvailableBackend()
	if availableBackend == nil || len(availableBackend) == 0 {
		return nil, fmt.Errorf("route %s has no backends available", proxyRoute.name)
	}
	director := func(req *http.Request) {
		// Increment the counter and wrap around using modulo
		index := atomic.AddUint32(&counter, 1) % uint32(len(availableBackend))
		backend := proxyRoute.backends[index]

		// Update the request URL to point to the selected backend
		backendURL, _ := url.Parse(backend.EndPoint)
		req.URL.Scheme = backendURL.Scheme
		req.URL.Host = backendURL.Host
		req.URL.Path = backendURL.Path + req.URL.Path
		req.Host = backendURL.Host
	}

	return &httputil.ReverseProxy{Director: director}, nil
}
func (b Backends) TotalWeight() int {
	total := 0
	for _, backend := range b {
		total += backend.Weight
	}
	return total
}

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
func (b Backends) HasPositiveWeight() bool {
	for _, backend := range b {
		if backend.Weight > 0 {
			return true
		}
	}
	return false
}
func (b Backends) AvailableBackend() Backends {
	backends := Backends{}
	for _, backend := range b {
		if !backend.unavailable {
			backends = append(backends, backend)
			continue
		}
	}
	return backends
}
