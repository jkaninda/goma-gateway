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
	"github.com/jkaninda/goma-gateway/internal/metrics"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"time"
)

func init() {
	_ = prometheus.Register(metrics.TotalRequests)
	_ = prometheus.Register(metrics.ResponseStatus)
	_ = prometheus.Register(metrics.HttpDuration)
}

// Initialize initializes the routes
func (gatewayServer GatewayServer) Initialize() *mux.Router {
	gateway := gatewayServer.gateway
	m := gatewayServer.middlewares
	redisBased := false
	if len(gateway.Redis.Addr) != 0 {
		redisBased = true
	}
	// Routes background healthcheck
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
		r.Use(middlewares.BlockExploitsMiddleware)
	}
	if gateway.RateLimit != 0 {
		// Add rate limit middlewares to all routes, if defined
		rateLimit := middlewares.RateLimit{
			Id:         "global_rate", // Generate a unique ID for routes
			Requests:   gateway.RateLimit,
			Window:     time.Minute, //  requests per minute
			Origins:    gateway.Cors.Origins,
			Hosts:      []string{},
			RedisBased: redisBased,
		}
		limiter := rateLimit.NewRateLimiterWindow()
		// Add rate limit middlewares
		r.Use(limiter.RateLimitMiddleware())
	}
	for rIndex, route := range gateway.Routes {
		if len(route.Path) != 0 {
			// Checks if route destination and backend are empty
			if len(route.Destination) == 0 && len(route.Backends) == 0 {
				logger.Fatal("Route %s : destination or backends should not be empty", route.Name)

			}
			// Apply middlewares to the route
			for _, middleware := range route.Middlewares {
				if middleware != "" {
					// Get Access middlewares if it does exist
					accessMiddleware, err := getMiddleware([]string{middleware}, m)
					if err != nil {
						logger.Error("Error: %v", err.Error())
					} else {
						// Apply access middlewares
						if accessMiddleware.Type == AccessMiddleware {
							blM := middlewares.AccessListMiddleware{
								Path: route.Path,
								List: accessMiddleware.Paths,
							}
							r.Use(blM.AccessMiddleware)

						}

					}
					// Get route authentication middlewares if it does exist
					routeMiddleware, err := getMiddleware([]string{middleware}, m)
					if err != nil {
						// Error: middlewares not found
						logger.Error("Error: %v", err.Error())
					} else {
						attachAuthMiddlewares(route, routeMiddleware, gateway, r)
					}
				} else {
					logger.Error("Error, middlewares path is empty")
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
				router.Use(middlewares.BlockExploitsMiddleware)
			}
			id := string(rune(rIndex))
			if len(route.Name) != 0 {
				// Use route name as ID
				id = util.Slug(route.Name)
			}
			// Apply route rate limit
			if route.RateLimit != 0 {
				rateLimit := middlewares.RateLimit{
					Id:         id, // Use route index as ID
					Requests:   route.RateLimit,
					Window:     time.Minute, //  requests per minute
					Origins:    route.Cors.Origins,
					Hosts:      route.Hosts,
					RedisBased: redisBased,
				}
				limiter := rateLimit.NewRateLimiterWindow()
				// Add rate limit middlewares
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
				pr := metrics.PrometheusRoute{
					Name: route.Name,
					Path: route.Path,
				}
				// Prometheus endpoint
				router.Use(pr.PrometheusMiddleware)
			}
			// Apply route Error interceptor middlewares
			if len(route.InterceptErrors) != 0 {
				interceptErrors := middlewares.InterceptErrors{
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
	r.Use(CORSHandler(gateway.Cors)) // Apply CORS middlewares
	// Apply errorInterceptor middlewares
	if len(gateway.InterceptErrors) != 0 {
		interceptErrors := middlewares.InterceptErrors{
			Errors:  gateway.InterceptErrors,
			Origins: gateway.Cors.Origins,
		}
		r.Use(interceptErrors.ErrorInterceptor)
	}

	return r

}

func attachAuthMiddlewares(route Route, routeMiddleware Middleware, gateway Gateway, r *mux.Router) {
	for _, middlewarePath := range routeMiddleware.Paths {
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
		secureRouter := r.PathPrefix(util.ParseRoutePath(route.Path, middlewarePath)).Subrouter()
		// Check Authentication middleware types
		switch routeMiddleware.Type {
		case BasicAuth:
			basicAuth, err := getBasicAuthMiddleware(routeMiddleware.Rule)
			if err != nil {
				logger.Error("Error: %s", err.Error())
			} else {
				authBasic := middlewares.AuthBasic{
					Username: basicAuth.Username,
					Password: basicAuth.Password,
					Headers:  nil,
					Params:   nil,
				}
				// Apply JWT authentication middlewares
				secureRouter.Use(authBasic.AuthMiddleware)
				secureRouter.Use(CORSHandler(route.Cors))
				secureRouter.PathPrefix("/").Handler(proxyRoute.ProxyHandler()) // Proxy handler
				secureRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())  // Proxy handler
			}
		case JWTAuth:
			jwt, err := getJWTMiddleware(routeMiddleware.Rule)
			if err != nil {
				logger.Error("Error: %s", err.Error())
			} else {
				jwtAuth := middlewares.JwtAuth{
					AuthURL:         jwt.URL,
					RequiredHeaders: jwt.RequiredHeaders,
					Headers:         jwt.Headers,
					Params:          jwt.Params,
					Origins:         gateway.Cors.Origins,
				}
				// Apply JWT authentication middlewares
				secureRouter.Use(jwtAuth.AuthMiddleware)
				secureRouter.Use(CORSHandler(route.Cors))
				secureRouter.PathPrefix("/").Handler(proxyRoute.ProxyHandler()) // Proxy handler
				secureRouter.PathPrefix("").Handler(proxyRoute.ProxyHandler())  // Proxy handler

			}
		case OAuth:
			oauth, err := oAuthMiddleware(routeMiddleware.Rule)
			if err != nil {
				logger.Error("Error: %s", err.Error())
			} else {
				redirectURL := "/callback" + route.Path
				if oauth.RedirectURL != "" {
					redirectURL = oauth.RedirectURL
				}
				amw := middlewares.Oauth{
					ClientID:     oauth.ClientID,
					ClientSecret: oauth.ClientSecret,
					RedirectURL:  redirectURL,
					Scopes:       oauth.Scopes,
					Endpoint: middlewares.OauthEndpoint{
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
					oauthRuler.RedirectPath = util.ParseRoutePath(route.Path, middlewarePath)
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
			if !doesExist(routeMiddleware.Type) {
				logger.Error("Unknown middlewares type %s", routeMiddleware.Type)
			}

		}

	}
}
