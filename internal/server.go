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
	"github.com/jkaninda/goma-gateway/internal/proxy"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Start / Start starts the server
func (g *Goma) Start() error {
	// Initialize redis if configured
	g.initRedis()
	defer g.closeRedis()

	logger.Info("Initializing routes...")
	err := g.Initialize()
	if err != nil {
		logger.Fatal("Failed to initialize routes", "error", err)
	}

	// Create router
	newRouter := g.NewRouter()
	err = newRouter.AddRoutes()
	if err != nil {
		logger.Error("Failed to add routes", "error", err)
		return err
	}

	logger.Info("Initializing route completed", "routes_count", len(g.dynamicRoutes), "middlewares_count", len(g.dynamicMiddlewares))

	// Configure TLS
	tlsConfig := &tls.Config{
		GetCertificate: certManager.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", "acme-tls/1"},
	}
	// Generate default certificate
	certificate, err := certManager.GenerateDefaultCertificate()
	if err != nil {
		return err
	}
	// Add default certificate
	certManager.AddCertificate("default", *certificate)
	printRoute(g.dynamicRoutes)
	// Watch for changes
	if g.gateway.ExtraConfig.Watch && len(g.gateway.ExtraConfig.Directory) > 0 {
		logger.Debug("Dynamic configuration watch enabled")
		go g.watchExtraConfig(newRouter)

	}
	// Start acme service
	go startAutoCert(g.dynamicRoutes)
	// Validate entrypoint
	g.gateway.EntryPoints.Validate()
	g.webServer = g.createServer(webAddress, g.createHTTPHandler(newRouter), nil)
	g.webSecureServer = g.createServer(webSecureAddress, newRouter, tlsConfig)

	// Create pass through proxy instance
	g.proxyServer = proxy.NewProxyServer(g.gateway.EntryPoints.PassThrough.Forwards, g.ctx, logger)

	// Start HTTP/HTTPS and proxy servers
	g.startServers()

	// Handle graceful shutdown
	return g.shutdown()
}

func (g *Goma) createServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         addr,
		WriteTimeout: time.Second * time.Duration(g.gateway.Timeouts.Write),
		ReadTimeout:  time.Second * time.Duration(g.gateway.Timeouts.Read),
		IdleTimeout:  time.Second * time.Duration(g.gateway.Timeouts.Idle),
		Handler:      handler,
		TLSConfig:    tlsConfig,
	}
}

// Create HTTP handler
func (g *Goma) createHTTPHandler(handler http.Handler) http.Handler {
	// Create the ACME reverse proxy once
	acmeProxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   acmeServerURL,
	})
	acmeProxy.Director = func(req *http.Request) {
		req.URL.Scheme = "http"
		req.URL.Host = acmeServerURL
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			logger.Debug("Handling ACME challenge", "path", r.URL.Path, "host", r.Host)
			acmeProxy.ServeHTTP(w, r)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (g *Goma) startServers() {
	// Start proxy server
	if err := g.proxyServer.Start(); err != nil {
		logger.Fatal("Failed to start proxy server", "error", err)
	}
	go func() {
		logger.Info("Starting Web server on", "addr", webAddress)
		if err := g.webServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("HTTP server error: %v", err)
		}
	}()

	go func() {
		logger.Info("Starting WebSecure server on ", "addr", webSecureAddress)
		if err := g.webSecureServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("HTTPS server error", "error", err)
		}
	}()

}

func (g *Goma) shutdown() error {
	signal.Notify(shutdownChan, syscall.SIGINT, syscall.SIGTERM)
	<-shutdownChan
	logger.Info("Shutting down Goma Gateway...")

	shutdownCtx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
	defer cancel()
	logger.Info("Shutting down HTTP/HTTPS servers")
	if err := g.webServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error shutting down HTTP server", "error", err)
	}

	if err := g.webSecureServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error shutting down HTTPS server", "error", err)
	}
	// stop TCP/UDP server
	g.proxyServer.Stop()
	logger.Info("Goma Gateway stopped")
	return nil
}
