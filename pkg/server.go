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

package pkg

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Start / Start starts the server
func (gatewayServer GatewayServer) Start() error {
	logger.Info("Initializing routes...")
	err := gatewayServer.Initialize()
	if err != nil {
		logger.Fatal("Failed to initialize routes: %v", err)
	}
	// Create router
	newRouter := gatewayServer.gateway.NewRouter()
	newRouter.AddRoutes(newRouter)

	logger.Debug("Routes count=%d, Middlewares count=%d", len(dynamicRoutes), len(dynamicMiddlewares))
	gatewayServer.initRedis()
	defer gatewayServer.closeRedis()
	// generate default tls config
	defaultCert, _ := gatewayServer.certManager.GenerateDefaultCertificate()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*defaultCert},
	}
	// Load certificates
	certs, _, _ := gatewayServer.initTLS()
	// Append certificates to the default tls config
	tlsConfig.Certificates = append(tlsConfig.Certificates, certs...)
	if !gatewayServer.gateway.DisableDisplayRouteOnStart {
		printRoute(dynamicRoutes)
	}
	// Watch for changes
	if gatewayServer.gateway.ExtraConfig.Watch {
		logger.Debug("Dynamic configuration watch enabled")
		go gatewayServer.watchExtraConfig(newRouter)

	}
	// Validate entrypoint
	gatewayServer.gateway.EntryPoints.Validate()

	httpServer := gatewayServer.createServer(webAddress, newRouter, nil)
	httpsServer := gatewayServer.createServer(webSecureAddress, newRouter, tlsConfig)

	// Start HTTP/HTTPS servers
	gatewayServer.startServers(httpServer, httpsServer, tlsConfig != nil)

	// Handle graceful shutdown
	return gatewayServer.shutdown(httpServer, httpsServer, tlsConfig != nil)
}

func (gatewayServer GatewayServer) createServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         addr,
		WriteTimeout: time.Second * time.Duration(gatewayServer.gateway.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(gatewayServer.gateway.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(gatewayServer.gateway.IdleTimeout),
		Handler:      handler,
		TLSConfig:    tlsConfig,
	}
}

func (gatewayServer GatewayServer) startServers(httpServer, httpsServer *http.Server, listenWithTLS bool) {
	go func() {
		logger.Info("Starting Web server on %s", webAddress)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("HTTP server error: %v", err)
		}
	}()

	if listenWithTLS {
		go func() {
			logger.Info("Starting WebSecure server on %s ", webSecureAddress)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatal("HTTPS server error: %v", err)
			}
		}()
	}
}

func (gatewayServer GatewayServer) shutdown(httpServer, httpsServer *http.Server, listenWithTLS bool) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down Goma Gateway...")

	shutdownCtx, cancel := context.WithTimeout(gatewayServer.ctx, 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Error shutting down HTTP server: %v", err)
	}

	if listenWithTLS {
		if err := httpsServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("Error shutting down HTTPS server: %v", err)
		}
	}
	return nil
}
