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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"time"
)

func init() {
	_ = prometheus.Register(totalRequests)
	_ = prometheus.Register(responseStatus)
	_ = prometheus.Register(httpDuration)
}

// Initialize the routes
func (gatewayServer GatewayServer) Initialize() *mux.Router {
	gateway := gatewayServer.gateway
	middlewares := gatewayServer.middlewares
	redisBased := false
	if len(gateway.Redis.Addr) != 0 {
		redisBased = true
	}
	//Routes background healthcheck
	routesHealthCheck(gateway.Routes)
	r := mux.NewRouter()
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: gateway.DisableRouteHealthCheckError,
		Routes:                       gateway.Routes,
	}
	if gateway.EnableMetrics {
		// Prometheus endpoint
		r.Path("/metrics").Handler(promhttp.Handler())
	}
	// Routes health check
	if !gateway.DisableHealthCheckStatus {
		r.HandleFunc("/healthz", heath.HealthCheckHandler).Methods("GET")
		r.HandleFunc("/health/routes", heath.HealthCheckHandler).Methods("GET")
	}

	// Health check
	r.HandleFunc("/health/live", heath.HealthReadyHandler).Methods("GET")
	r.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")
	// Enable common exploits
	if gateway.BlockCommonExploits {
		logger.Info("Block common exploits enabled")
		r.Use(middleware.BlockExploitsMiddleware)
	}
	if gateway.RateLimit > 0 {
		// Add rate limit middleware to all routes, if defined
		rateLimit := middleware.RateLimit{
			Id:         "global_rate", //Generate a unique ID for routes
			Requests:   gateway.RateLimit,
			Window:     time.Minute, //  requests per minute
			Origins:    gateway.Cors.Origins,
			Hosts:      []string{},
			RedisBased: redisBased,
		}
		limiter := rateLimit.NewRateLimiterWindow()
		// Add rate limit middleware
		r.Use(limiter.RateLimitMiddleware())
	}
	for rIndex, route := range gateway.Routes {
		if route.Path != "" {
			if route.Destination == "" && len(route.Backends) == 0 {
				logger.Fatal("Route %s : destination or backends should not be empty", route.Name)

			}
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
								path:               route.Path,
								rewrite:            route.Rewrite,
								destination:        route.Destination,
								backends:           route.Backends,
								disableHostFording: route.DisableHostFording,
								methods:            route.Methods,
								cors:               route.Cors,
								insecureSkipVerify: route.InsecureSkipVerify,
							}
							secureRouter := r.PathPrefix(util.ParseRoutePath(route.Path, midPath)).Subrouter()
							//callBackRouter := r.PathPrefix(util.ParseRoutePath(route.Path, "/callback")).Subrouter()
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
										Origins:         gateway.Cors.Origins,
									}
									// Apply JWT authentication middleware
									secureRouter.Use(amw.AuthMiddleware)
									secureRouter.Use(CORSHandler(route.Cors))
									secureRouter.PathPrefix("/").Handler(proxyRoute.ProxyHandler()) // Proxy handler
									secureRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())  // Proxy handler

								}
							case OAuth, "openid":
								oauth, err := oAuthMiddleware(rMiddleware.Rule)
								if err != nil {
									logger.Error("Error: %s", err.Error())
								} else {
									redirectURL := "/callback" + route.Path
									if oauth.RedirectURL != "" {
										redirectURL = oauth.RedirectURL
									}
									amw := middleware.Oauth{
										ClientID:     oauth.ClientID,
										ClientSecret: oauth.ClientSecret,
										RedirectURL:  redirectURL,
										Scopes:       oauth.Scopes,
										Endpoint: middleware.OauthEndpoint{
											AuthURL:     oauth.Endpoint.AuthURL,
											TokenURL:    oauth.Endpoint.TokenURL,
											UserInfoURL: oauth.Endpoint.UserInfoURL,
										},
										State:     oauth.State,
										Origins:   gateway.Cors.Origins,
										JWTSecret: oauth.JWTSecret,
										Provider:  oauth.Provider,
									}
									oauthRuler := oauthRulerMiddleware(amw)
									// Check if a cookie path is defined
									if oauthRuler.CookiePath == "" {
										oauthRuler.CookiePath = route.Path
									}
									// Check if a RedirectPath is defined
									if oauthRuler.RedirectPath == "" {
										oauthRuler.RedirectPath = util.ParseRoutePath(route.Path, midPath)
									}
									if oauthRuler.Provider == "" {
										oauthRuler.Provider = "custom"
									}
									secureRouter.Use(amw.AuthMiddleware)
									secureRouter.Use(CORSHandler(route.Cors))
									secureRouter.PathPrefix("/").Handler(proxyRoute.ProxyHandler()) // Proxy handler
									secureRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())  // Proxy handler
									// Callback route
									r.HandleFunc(util.UrlParsePath(redirectURL), oauthRuler.callbackHandler).Methods("GET")
								}
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
				path:               route.Path,
				rewrite:            route.Rewrite,
				destination:        route.Destination,
				backends:           route.Backends,
				methods:            route.Methods,
				disableHostFording: route.DisableHostFording,
				cors:               route.Cors,
				insecureSkipVerify: route.InsecureSkipVerify,
			}
			// create route
			router := r.PathPrefix(route.Path).Subrouter()
			// Apply common exploits to the route
			// Enable common exploits
			if route.BlockCommonExploits {
				logger.Info("Block common exploits enabled")
				router.Use(middleware.BlockExploitsMiddleware)
			}
			// Apply route rate limit
			if route.RateLimit > 0 {
				rateLimit := middleware.RateLimit{
					Id:         string(rune(rIndex)), // Use route index as ID
					Requests:   route.RateLimit,
					Window:     time.Minute, //  requests per minute
					Origins:    route.Cors.Origins,
					Hosts:      route.Hosts,
					RedisBased: redisBased,
				}
				limiter := rateLimit.NewRateLimiterWindow()
				// Add rate limit middleware
				router.Use(limiter.RateLimitMiddleware())
			}
			// Apply route Cors
			router.Use(CORSHandler(route.Cors))
			if len(route.Hosts) > 0 {
				for _, host := range route.Hosts {
					router.Host(host).PathPrefix("").Handler(proxyRoute.ProxyHandler())
				}
			} else {
				router.PathPrefix("").Handler(proxyRoute.ProxyHandler())
			}
			if gateway.EnableMetrics {
				pr := PrometheusRoute{
					name: route.Name,
					path: route.Path,
				}
				// Prometheus endpoint
				router.Use(pr.prometheusMiddleware)
			}
			// Apply route Error interceptor middleware
			if len(route.InterceptErrors) != 0 {
				interceptErrors := middleware.InterceptErrors{
					Origins: route.Cors.Origins,
					Errors:  route.InterceptErrors,
				}
				router.Use(interceptErrors.ErrorInterceptor)
			}
		} else {
			logger.Error("Error, path is empty in route %s", route.Name)
			logger.Error("Route path ignored: %s", route.Path)
		}
	}
	// Apply global Cors middlewares
	r.Use(CORSHandler(gateway.Cors)) // Apply CORS middleware
	// Apply errorInterceptor middleware
	if len(gateway.InterceptErrors) != 0 {
		interceptErrors := middleware.InterceptErrors{
			Errors:  gateway.InterceptErrors,
			Origins: gateway.Cors.Origins,
		}
		r.Use(interceptErrors.ErrorInterceptor)
	}

	return r

}
