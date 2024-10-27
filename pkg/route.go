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
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jkaninda/goma-gateway/internal/logger"
	"github.com/jkaninda/goma-gateway/pkg/middleware"
	"github.com/jkaninda/goma-gateway/util"
	"time"
)

func (gatewayServer GatewayServer) Initialize() *mux.Router {
	gateway := gatewayServer.gateway
	middlewares := gatewayServer.middlewares
	r := mux.NewRouter()
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: gateway.DisableRouteHealthCheckError,
		Routes:                       gateway.Routes,
	}
	// Define the health check route
	r.HandleFunc("/health", heath.HealthCheckHandler).Methods("GET")
	r.HandleFunc("/healthz", heath.HealthCheckHandler).Methods("GET")
	// Apply global Cors middlewares
	r.Use(CORSHandler(gateway.Cors)) // Apply CORS middleware
	if gateway.RateLimiter != 0 {
		//rateLimiter := middleware.NewRateLimiter(gateway.RateLimiter, time.Minute)
		limiter := middleware.NewRateLimiterWindow(gateway.RateLimiter, time.Minute) //  requests per minute
		// Add rate limit middleware to all routes, if defined
		r.Use(limiter.RateLimitMiddleware())
	}
	for _, route := range gateway.Routes {
		blM := middleware.BlockListMiddleware{
			Path: route.Path,
			List: route.Blocklist,
		}
		// Add block access middleware to all route, if defined
		r.Use(blM.BlocklistMiddleware)
		//if route.Middlewares != nil {
		for _, mid := range route.Middlewares {
			secureRouter := r.PathPrefix(util.ParseURLPath(route.Path + mid.Path)).Subrouter()
			proxyRoute := ProxyRoute{
				path:            route.Path,
				rewrite:         route.Rewrite,
				destination:     route.Destination,
				disableXForward: route.DisableHeaderXForward,
				cors:            route.Cors,
			}
			rMiddleware, err := searchMiddleware(mid.Rules, middlewares)
			if err != nil {
				logger.Error("Middleware name not found")
			} else {
				//Check Authentication middleware
				switch rMiddleware.Type {
				case "basic":
					basicAuth, err := ToBasicAuth(rMiddleware.Rule)
					if err != nil {

						logger.Error("Error: %s", err.Error())
					} else {
						amw := middleware.AuthBasic{
							Username: basicAuth.Username,
							Password: basicAuth.Password,
							Headers:  nil,
							Params:   nil,
						}
						// Apply JWT authentication middleware
						secureRouter.Use(amw.AuthMiddleware)
					}
				case "jwt":
					jwt, err := ToJWTRuler(rMiddleware.Rule)
					if err != nil {

					} else {
						amw := middleware.AuthJWT{
							AuthURL:         jwt.URL,
							RequiredHeaders: jwt.RequiredHeaders,
							Headers:         jwt.Headers,
							Params:          jwt.Params,
						}
						// Apply JWT authentication middleware
						secureRouter.Use(amw.AuthMiddleware)

					}
				default:
					logger.Error("Unknown middleware type %s", rMiddleware.Type)

				}

			}
			secureRouter.Use(CORSHandler(route.Cors))
			secureRouter.PathPrefix("/").Handler(proxyRoute.ProxyHandler()) // Proxy handler
			secureRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())  // Proxy handler
		}
		proxyRoute := ProxyRoute{
			path:            route.Path,
			rewrite:         route.Rewrite,
			destination:     route.Destination,
			disableXForward: route.DisableHeaderXForward,
			cors:            route.Cors,
		}

		router := r.PathPrefix(route.Path).Subrouter()
		router.Use(CORSHandler(route.Cors))
		router.PathPrefix("/").Handler(proxyRoute.ProxyHandler())
	}
	return r

}

func printRoute(routes []Route) {
	t := table.NewWriter()
	t.AppendHeader(table.Row{"Name", "Route", "Rewrite", "Destination"})
	for _, route := range routes {
		t.AppendRow(table.Row{route.Name, route.Path, route.Rewrite, route.Destination})
	}
	fmt.Println(t.Render())
}
