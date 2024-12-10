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
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
)

// ProxyHandler proxies requests to the backend
func (proxyRoute ProxyRoute) ProxyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("%s %s %s %s", r.Method, getRealIP(r), r.URL.Path, r.UserAgent())
		logger.Trace("Request params: %s", r.URL.RawQuery)
		// Check Method if is allowed
		if len(proxyRoute.methods) > 0 {
			if !slices.Contains(proxyRoute.methods, r.Method) {
				logger.Error("%s Method is not allowed", r.Method)
				middlewares.RespondWithError(w, r, http.StatusMethodNotAllowed, fmt.Sprintf("%d %s method is not allowed", http.StatusMethodNotAllowed, r.Method), proxyRoute.cors.Origins)
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
			middlewares.RespondWithError(w, r, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), nil)
			return
		}
		r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
		r.Header.Set("X-Forwarded-For", getRealIP(r))
		r.Header.Set("X-Real-IP", getRealIP(r))
		// Update the headers to allow for SSL redirection
		if proxyRoute.disableHostFording {
			r.URL.Scheme = targetURL.Scheme
			r.Host = targetURL.Host
		}
		backendURL, _ := url.Parse(proxyRoute.destination)
		if len(proxyRoute.backends) != 0 {
			// Select the next backend URL
			backendURL = getNextBackend(proxyRoute.backends)
		}
		// Create proxy
		proxy := httputil.NewSingleHostReverseProxy(backendURL)
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
