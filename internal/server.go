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
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Start / Start starts the server
func (gatewayServer *GatewayServer) Start() error {
	logger.Info("Initializing routes...")
	err := gatewayServer.Initialize()
	if err != nil {
		logger.Fatal("Failed to initialize routes", "error", err)
	}

	// Create router
	newRouter := gatewayServer.gateway.NewRouter()
	newRouter.AddRoutes(newRouter)

	logger.Debug("Initializing route completed", "route_count", len(dynamicRoutes), "middleware_count", len(dynamicMiddlewares))
	gatewayServer.initRedis()
	defer gatewayServer.closeRedis()
	// Configure TLS
	tlsConfig := &tls.Config{
		GetCertificate: certManager.GetCertificate,
	}
	// Generate default certificate
	certificate, err := certManager.GenerateDefaultCertificate()
	if err != nil {
		return err
	}
	// Add default certificate
	certManager.AddCertificate("default", *certificate)
	if !gatewayServer.gateway.DisableDisplayRouteOnStart {
		printRoute(dynamicRoutes)
	}
	// Watch for changes
	if gatewayServer.gateway.ExtraConfig.Watch {
		logger.Debug("Dynamic configuration watch enabled")
		go gatewayServer.watchExtraConfig(newRouter)

	}

	// Start acme service
	go startAutoCert()
	// Validate entrypoint
	gatewayServer.gateway.EntryPoints.Validate()
	httpServer := gatewayServer.createServer(webAddress, gatewayServer.createHTTPHandler(newRouter), nil)
	httpsServer := gatewayServer.createServer(webSecureAddress, newRouter, tlsConfig)

	// Start HTTP/HTTPS servers
	gatewayServer.startServers(httpServer, httpsServer)

	// Handle graceful shutdown
	return gatewayServer.shutdown(httpServer, httpsServer)
}

func (gatewayServer *GatewayServer) createServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         addr,
		WriteTimeout: time.Second * time.Duration(gatewayServer.gateway.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(gatewayServer.gateway.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(gatewayServer.gateway.IdleTimeout),
		Handler:      handler,
		TLSConfig:    tlsConfig,
	}
}

// Create HTTP handler
func (gatewayServer *GatewayServer) createHTTPHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle ACME challenges
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			logger.Debug("Handling ACME challenge", "path", r.URL.Path, "host", r.Host)
			proxy := httputil.NewSingleHostReverseProxy(&url.URL{
				Scheme: "http",
				Host:   "localhost:5002",
			})
			// Forward the request
			proxy.ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (gatewayServer *GatewayServer) startServers(httpServer, httpsServer *http.Server) {
	go func() {
		logger.Info("Starting Web server on", "addr", webAddress)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("HTTP server error: %v", err)
		}
	}()

	go func() {
		logger.Info("Starting WebSecure server on ", "addr", webSecureAddress)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("HTTPS server error", "error", err)
		}
	}()

}

func (gatewayServer *GatewayServer) shutdown(httpServer, httpsServer *http.Server) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down Goma Gateway...")

	shutdownCtx, cancel := context.WithTimeout(gatewayServer.ctx, 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error shutting down HTTP server", "error", err)
	}

	if err := httpsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error shutting down HTTPS server", "error", err)
	}

	return nil
}
