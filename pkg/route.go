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
	"github.com/gorilla/mux"
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
	r.HandleFunc("/healthz", heath.HealthCheckHandler).Methods("GET")
	r.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")
	// Apply global Cors middlewares
	r.Use(CORSHandler(gateway.Cors)) // Apply CORS middleware
	if gateway.RateLimiter != 0 {
		//rateLimiter := middleware.NewRateLimiter(gateway.RateLimiter, time.Minute)
		limiter := middleware.NewRateLimiterWindow(gateway.RateLimiter, time.Minute) //  requests per minute
		// Add rate limit middleware to all routes, if defined
		r.Use(limiter.RateLimitMiddleware())
	}
	for _, route := range gateway.Routes {
		if route.Path != "" {
			blM := middleware.BlockListMiddleware{
				Path: route.Path,
				List: route.Blocklist,
			}
			// Add block access middleware to all route, if defined
			r.Use(blM.BlocklistMiddleware)
			// Apply route middleware
			for _, mid := range route.Middlewares {
				if mid.Path != "" {
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
						logger.Error("Error: %v", err.Error())
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
								secureRouter.Use(CORSHandler(route.Cors))
								secureRouter.PathPrefix("/").Handler(proxyRoute.ProxyHandler()) // Proxy handler
								secureRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())  // Proxy handler
							}
						case "jwt":
							jwt, err := ToJWTRuler(rMiddleware.Rule)
							if err != nil {
								logger.Error("Error: %s", err.Error())
							} else {
								amw := middleware.AuthJWT{
									AuthURL:         jwt.URL,
									RequiredHeaders: jwt.RequiredHeaders,
									Headers:         jwt.Headers,
									Params:          jwt.Params,
								}
								// Apply JWT authentication middleware
								secureRouter.Use(amw.AuthMiddleware)
								secureRouter.Use(CORSHandler(route.Cors))
								secureRouter.PathPrefix("/").Handler(proxyRoute.ProxyHandler()) // Proxy handler
								secureRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())  // Proxy handler

							}
						default:
							logger.Error("Unknown middleware type %s", rMiddleware.Type)

						}

					}
				} else {
					logger.Error("Error, middleware path is empty")
					logger.Error("Middleware ignored")
				}
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
			//Domain/host based request routing
			if route.Host != "" {
				router.Host(route.Host).PathPrefix("").Handler(proxyRoute.ProxyHandler())
			} else {
				router.PathPrefix("").Handler(proxyRoute.ProxyHandler())
			}
		} else {
			logger.Error("Error, path is empty in route %s", route.Name)
			logger.Info("Route path ignored: %s", route.Path)
		}
	}
	return r

}
