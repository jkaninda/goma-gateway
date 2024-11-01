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
	"encoding/json"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type ProxyRoute struct {
	path            string
	rewrite         string
	destination     string
	cors            Cors
	disableXForward bool
}

// ProxyHandler proxies requests to the backend
func (proxyRoute ProxyRoute) ProxyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realIP := getRealIP(r)
		logger.Info("%s %s %s %s", r.Method, realIP, r.URL, r.UserAgent())
		w.Header().Set("Proxied-By", gatewayName) //Set Server name
		w.Header().Set("Server", serverName)
		// Set CORS headers from the cors config
		//Update Cors Headers
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			err := json.NewEncoder(w).Encode(ErrorResponse{
				Message: "Internal server error",
				Code:    http.StatusInternalServerError,
				Success: false,
			})
			if err != nil {
				return
			}
			return
		}
		// Update the headers to allow for SSL redirection
		if !proxyRoute.disableXForward {
			r.URL.Host = targetURL.Host
			r.URL.Scheme = targetURL.Scheme
			r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))
			r.Header.Set("X-Forwarded-For", realIP)
			r.Header.Set("X-Real-IP", realIP)
			r.Host = targetURL.Host
		}
		// Create proxy
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		// Rewrite
		if proxyRoute.path != "" && proxyRoute.rewrite != "" {
			// Rewrite the path
			if strings.HasPrefix(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path)) {
				r.URL.Path = strings.Replace(r.URL.Path, fmt.Sprintf("%s/", proxyRoute.path), proxyRoute.rewrite, 1)
			}
		}
		// Custom error handler for proxy errors
		proxy.ErrorHandler = ProxyErrorHandler
		proxy.ServeHTTP(w, r)
	}
}
