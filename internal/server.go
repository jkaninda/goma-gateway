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
	"context"
	"crypto/tls"
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/middleware"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/redis/go-redis/v9"
	"net/http"
	"os"
	"sync"
	"time"
)

// Start starts the server
func (gatewayServer GatewayServer) Start(ctx context.Context) error {
	logger.Info("Initializing routes...")
	route := gatewayServer.Initialize()
	gateway := gatewayServer.gateway
	logger.Debug("Routes count=%d Middlewares count=%d", len(gatewayServer.gateway.Routes), len(gatewayServer.middlewares))
	logger.Info("Initializing routes...done")
	if len(gateway.Redis.Addr) != 0 {
		middleware.InitRedis(gateway.Redis.Addr, gateway.Redis.Password)
		defer func(Rdb *redis.Client) {
			err := Rdb.Close()
			if err != nil {
				logger.Error("Redis connection closed with error: %v", err)
			}
		}(middleware.Rdb)
	}

	tlsConfig := &tls.Config{}
	var listenWithTLS = false
	if cert := gatewayServer.gateway.SSLCertFile; cert != "" && gatewayServer.gateway.SSLKeyFile != "" {
		tlsConf, err := loadTLS(cert, gatewayServer.gateway.SSLKeyFile)
		if err != nil {
			return err
		}
		tlsConfig = tlsConf
		listenWithTLS = true

	}
	// HTTP Server
	httpServer := &http.Server{
		Addr:         ":8080",
		WriteTimeout: time.Second * time.Duration(gatewayServer.gateway.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(gatewayServer.gateway.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(gatewayServer.gateway.IdleTimeout),
		Handler:      route, // Pass our instance of gorilla/mux in.
	}
	// HTTPS Server
	httpsServer := &http.Server{
		Addr:         ":8443",
		WriteTimeout: time.Second * time.Duration(gatewayServer.gateway.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(gatewayServer.gateway.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(gatewayServer.gateway.IdleTimeout),
		Handler:      route, // Pass our instance of gorilla/mux in.
		TLSConfig:    tlsConfig,
	}
	if !gatewayServer.gateway.DisableDisplayRouteOnStart {
		printRoute(gatewayServer.gateway.Routes)
	}
	// Set KeepAlive
	httpServer.SetKeepAlivesEnabled(!gatewayServer.gateway.DisableKeepAlive)
	go func() {
		logger.Info("Starting HTTP server listen=0.0.0.0:8080")
		if err := httpServer.ListenAndServe(); err != nil {
			logger.Fatal("Error starting Goma Gateway HTTP server: %v", err)
		}
	}()
	go func() {
		if listenWithTLS {
			logger.Info("Starting HTTPS server listen=0.0.0.0:8443")
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
				logger.Fatal("Error starting Goma Gateway HTTPS server: %v", err)
			}
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx := context.Background()
		shutdownCtx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "error shutting down HTTP server: %s\n", err)
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx := context.Background()
		shutdownCtx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
		defer cancel()
		if listenWithTLS {
			if err := httpsServer.Shutdown(shutdownCtx); err != nil {
				_, err := fmt.Fprintf(os.Stderr, "error shutting HTTPS server: %s\n", err)
				if err != nil {
					return
				}
			}
		}
	}()
	wg.Wait()
	return nil

}
