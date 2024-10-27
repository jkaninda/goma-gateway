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
	"fmt"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"net/http"
	"os"
	"sync"
	"time"
)

func (gatewayServer GatewayServer) Start(ctx context.Context) error {
	logger.Info("Initializing routes...")
	route := gatewayServer.Initialize()
	logger.Info("Initializing routes...done")
	srv := &http.Server{
		Addr:         gatewayServer.gateway.ListenAddr,
		WriteTimeout: time.Second * time.Duration(gatewayServer.gateway.WriteTimeout),
		ReadTimeout:  time.Second * time.Duration(gatewayServer.gateway.ReadTimeout),
		IdleTimeout:  time.Second * time.Duration(gatewayServer.gateway.IdleTimeout),
		Handler:      route, // Pass our instance of gorilla/mux in.
	}
	if !gatewayServer.gateway.DisableDisplayRouteOnStart {
		printRoute(gatewayServer.gateway.Routes)
	}
	go func() {

		logger.Info("Started Goma Gateway server on %v", gatewayServer.gateway.ListenAddr)
		if err := srv.ListenAndServe(); err != nil {
			logger.Error("Error starting Goma Gateway server: %v", err)
		}
	}()
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		<-ctx.Done()
		shutdownCtx := context.Background()
		shutdownCtx, cancel := context.WithTimeout(shutdownCtx, 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_, err := fmt.Fprintf(os.Stderr, "error shutting down Goma Gateway server: %s\n", err)
			if err != nil {
				return
			}
		}
	}()
	wg.Wait()
	return nil

}
