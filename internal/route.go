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
	"github.com/jkaninda/goma-gateway/internal/middleware"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"time"
)

// Initialize the routes
func (gatewayServer GatewayServer) Initialize() *mux.Router {
	gateway := gatewayServer.gateway
	middlewares := gatewayServer.middlewares
	r := mux.NewRouter()
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: gateway.DisableRouteHealthCheckError,
		Routes:                       gateway.Routes,
	}
	// Routes health check
	if !gateway.DisableHealthCheckStatus {
		r.HandleFunc("/healthz", heath.HealthCheckHandler).Methods("GET")
		r.HandleFunc("/health/routes", heath.HealthCheckHandler).Methods("GET")
	}
	// Health check
	r.HandleFunc("/health/live", heath.HealthReadyHandler).Methods("GET")
	r.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")

	if gateway.RateLimiter != 0 {
		//rateLimiter := middleware.NewRateLimiter(gateway.RateLimiter, time.Minute)
		limiter := middleware.NewRateLimiterWindow(gateway.RateLimiter, time.Minute) //  requests per minute
		// Add rate limit middleware to all routes, if defined
		r.Use(limiter.RateLimitMiddleware())
	}
	for _, route := range gateway.Routes {
		if route.Path != "" {

			// Apply middlewares to route
			for _, mid := range route.Middlewares {
				if mid != "" {
					// Get Access middleware if it does exist
					accessMiddleware, err := getMiddleware([]string{mid}, middlewares)
					if err != nil {
						logger.Error("Error: %v", err.Error())
					} else {
						// Apply access middleware
						if accessMiddleware.Type == AccessMiddleware {
							blM := middleware.AccessListMiddleware{
								Path: route.Path,
								List: accessMiddleware.Paths,
							}
							r.Use(blM.AccessMiddleware)

						}

					}
					// Get route authentication middleware if it does exist
					rMiddleware, err := getMiddleware([]string{mid}, middlewares)
					if err != nil {
						//Error: middleware not found
						logger.Error("Error: %v", err.Error())
					} else {
						for _, midPath := range rMiddleware.Paths {
							proxyRoute := ProxyRoute{
								path:            route.Path,
								rewrite:         route.Rewrite,
								destination:     route.Destination,
								disableXForward: route.DisableHeaderXForward,
								cors:            route.Cors,
							}
							secureRouter := r.PathPrefix(util.ParseRoutePath(route.Path, midPath)).Subrouter()
							//Check Authentication middleware
							switch rMiddleware.Type {
							case BasicAuth:
								basicAuth, err := getBasicAuthMiddleware(rMiddleware.Rule)
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
							case JWTAuth:
								jwt, err := getJWTMiddleware(rMiddleware.Rule)
								if err != nil {
									logger.Error("Error: %s", err.Error())
								} else {
									amw := middleware.JwtAuth{
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
							case "OAuth":
								logger.Error("OAuth is not yet implemented")
								logger.Info("Auth middleware ignored")
							default:
								if !doesExist(rMiddleware.Type) {
									logger.Error("Unknown middleware type %s", rMiddleware.Type)
								}

							}

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
			// Apply route Cors
			router.Use(CORSHandler(route.Cors))
			if route.Host != "" {
				router.Host(route.Host).PathPrefix("").Handler(proxyRoute.ProxyHandler())
			} else {
				router.PathPrefix("").Handler(proxyRoute.ProxyHandler())
			}
		} else {
			logger.Error("Error, path is empty in route %s", route.Name)
			logger.Debug("Route path ignored: %s", route.Path)
		}
	}
	// Apply global Cors middlewares
	r.Use(CORSHandler(gateway.Cors)) // Apply CORS middleware
	// Apply errorInterceptor middleware
	interceptErrors := middleware.InterceptErrors{
		Errors: gateway.InterceptErrors,
	}
	r.Use(interceptErrors.ErrorInterceptor)
	return r

}
