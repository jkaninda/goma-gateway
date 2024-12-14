package internal

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
	"slices"
	"sort"
)

// init initializes prometheus metrics
func init() {
	_ = prometheus.Register(metrics.TotalRequests)
	_ = prometheus.Register(metrics.ResponseStatus)
	_ = prometheus.Register(metrics.HttpDuration)
}

// Initialize initializes the routes
func (gatewayServer GatewayServer) Initialize() *mux.Router {
	gateway := gatewayServer.gateway
	dynamicRoutes = gateway.Routes
	dynamicMiddlewares = gatewayServer.middlewares
	if len(gateway.ExtraRoutes.Directory) == 0 {
		gateway.ExtraRoutes.Directory = ExtraDir
	}
	// Load Extra Middlewares
	logger.Info("Loading additional configurations...")
	extraMiddlewares, err := loadExtraMiddlewares(gateway.ExtraRoutes.Directory)
	if err == nil {
		dynamicMiddlewares = append(dynamicMiddlewares, extraMiddlewares...)
		logger.Info("Loaded %d additional middlewares", len(extraMiddlewares))

	}
	// Load Extra Routes
	extraRoutes, err := loadExtraRoutes(gateway.ExtraRoutes.Directory)
	if err == nil {
		dynamicRoutes = append(dynamicRoutes, extraRoutes...)
		logger.Info("Loaded %d additional routes", len(extraRoutes))

	}
	// Check configs
	err = checkConfig(dynamicRoutes, dynamicMiddlewares)
	if err != nil {
		logger.Fatal("Error: %v", err)
	}
	if len(gateway.Redis.Addr) != 0 {
		redisBased = true
	}
	// Sort routes by path in descending order
	sort.Slice(dynamicRoutes, func(i, j int) bool {
		return len(dynamicRoutes[i].Path) > len(dynamicRoutes[j].Path)
	})
	dynamicRoutes = initRoutes(dynamicRoutes)

	// Routes background healthcheck
	routesHealthCheck(dynamicRoutes)

	r := mux.NewRouter()
	heath := HealthCheckRoute{
		DisableRouteHealthCheckError: gateway.DisableRouteHealthCheckError,
		Routes:                       dynamicRoutes,
	}
	if gateway.EnableMetrics {
		// Prometheus endpoint
		r.Path("/metrics").Handler(promhttp.Handler())
	}
	// Routes health check
	if !gateway.DisableHealthCheckStatus {
		r.HandleFunc("/health/routes", heath.HealthCheckHandler).Methods("GET") // Deprecated
		r.HandleFunc("/healthz/routes", heath.HealthCheckHandler).Methods("GET")
	}

	// Health check
	r.HandleFunc("/health/live", heath.HealthReadyHandler).Methods("GET") // Deprecated
	r.HandleFunc("/readyz", heath.HealthReadyHandler).Methods("GET")
	r.HandleFunc("/healthz", heath.HealthReadyHandler).Methods("GET")
	// Enable common exploits
	if gateway.BlockCommonExploits {
		logger.Info("Block common exploits enabled")
		r.Use(middlewares.BlockExploitsMiddleware)
	}
	// check if RateLimit is set
	if gateway.RateLimit != 0 {
		// Add rate limit middlewares to all routes, if defined
		rateLimit := middlewares.RateLimit{
			Id:         "global_rate", // Generate a unique ID for routes
			Unit:       "minute",
			Requests:   gateway.RateLimit,
			Origins:    gateway.Cors.Origins,
			Hosts:      []string{},
			RedisBased: redisBased,
		}
		limiter := rateLimit.NewRateLimiterWindow()
		// Add rate limit middlewares
		r.Use(limiter.RateLimitMiddleware())
	}
	for rIndex, route := range dynamicRoutes {

		// create route
		router := r.PathPrefix(route.Path).Subrouter()
		if len(route.Path) != 0 {
			// Checks if route destination and backend are empty
			if len(route.Destination) == 0 && len(route.Backends) == 0 {
				logger.Fatal("Route %s : destination or backends should not be empty", route.Name)

			}
			logger.Info("ID: %s", route.id)
			if route.DisableHostForwarding {
				logger.Info("Route %s : disabled host forwarding", route.Name)

			}
			proxyRoute := ProxyRoute{
				path:                  route.Path,
				rewrite:               route.Rewrite,
				destination:           route.Destination,
				backends:              route.Backends,
				methods:               route.Methods,
				disableHostForwarding: route.DisableHostForwarding,
				cors:                  route.Cors,
				insecureSkipVerify:    route.InsecureSkipVerify,
			}
			attachMiddlewares(rIndex, route, gateway, router)
			// Apply route Cors
			router.Use(CORSHandler(route.Cors))
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
			if len(route.Hosts) != 0 {
				for _, host := range route.Hosts {
					router.Host(host).PathPrefix("").Handler(proxyRoute.ProxyHandler())
				}
			} else {
				router.PathPrefix("").Handler(proxyRoute.ProxyHandler())
			}

		} else {
			logger.Error("Error, path is empty in route %s", route.Name)
			logger.Error("Route path ignored: %s", route.Path)
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

	}

	return r

}

// attachMiddlewares attach middlewares to the route
func attachMiddlewares(rIndex int, route Route, gateway Gateway, router *mux.Router) {
	// Apply middlewares to the route
	for _, middleware := range route.Middlewares {
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
				Unit:       "minute",
				Id:         id, // Use route index as ID
				Requests:   route.RateLimit,
				Origins:    route.Cors.Origins,
				Hosts:      route.Hosts,
				RedisBased: redisBased,
			}
			limiter := rateLimit.NewRateLimiterWindow()
			// Add rate limit middlewares
			router.Use(limiter.RateLimitMiddleware())
		}
		if len(middleware) != 0 {
			// Get Access middlewares if it does exist
			mid, err := getMiddleware([]string{middleware}, dynamicMiddlewares)
			if err != nil {
				logger.Error("Error: %v", err.Error())
			} else {
				// Apply access middlewares
				if mid.Type == AccessMiddleware {
					blM := middlewares.AccessListMiddleware{
						Path:    route.Path,
						List:    mid.Paths,
						Origins: route.Cors.Origins,
					}
					router.Use(blM.AccessMiddleware)
				}

				// Apply Rate limit middleware
				if slices.Contains(RateLimitMiddleware, mid.Type) {
					rateLimitMid, err := rateLimitMiddleware(mid.Rule)
					if err != nil {
						logger.Error("Error: %v", err.Error())
					}
					if rateLimitMid.RequestsPerUnit != 0 && route.RateLimit == 0 {
						rateLimit := middlewares.RateLimit{
							Unit:       rateLimitMid.Unit,
							Id:         id, // Use route index as ID
							Requests:   rateLimitMid.RequestsPerUnit,
							Origins:    route.Cors.Origins,
							Hosts:      route.Hosts,
							RedisBased: redisBased,
							PathBased:  true,
							Paths:      util.AddPrefixPath(route.Path, mid.Paths),
						}
						limiter := rateLimit.NewRateLimiterWindow()
						// Apply rate limiter middlewares
						router.Use(limiter.RateLimitMiddleware())

					}

				}
				// AccessPolicy
				if accessPolicy == mid.Type {
					a, err := getAccessPoliciesMiddleware(mid.Rule)
					if err != nil {
						logger.Error("Error: %v, middleware not applied", err.Error())
					}
					if len(a.SourceRanges) != 0 {
						access := middlewares.AccessPolicy{
							SourceRanges: a.SourceRanges,
							Action:       a.Action,
							Origins:      route.Cors.Origins,
						}
						router.Use(access.AccessPolicyMiddleware)
					}
				}

			}

			// Get route authentication middlewares if it does exist
			routeMiddleware, err := getMiddleware([]string{middleware}, dynamicMiddlewares)
			if err != nil {
				// Error: middlewares not found
				logger.Error("Error: %v", err.Error())
			} else {
				attachAuthMiddlewares(route, routeMiddleware, gateway, router)
			}
		} else {
			logger.Error("Error, middlewares path is empty")
			logger.Error("Middleware ignored")
		}
	}

}

func attachAuthMiddlewares(route Route, routeMiddleware Middleware, gateway Gateway, r *mux.Router) {
	// Check Authentication middleware types
	switch routeMiddleware.Type {
	case BasicAuth:
		basicAuth, err := getBasicAuthMiddleware(routeMiddleware.Rule)
		if err != nil {
			logger.Error("Error: %s", err.Error())
		} else {
			authBasic := middlewares.AuthBasic{
				Path:     route.Path,
				Paths:    routeMiddleware.Paths,
				Username: basicAuth.Username,
				Password: basicAuth.Password,
				Headers:  nil,
				Params:   nil,
			}
			// Apply JWT authentication middlewares
			r.Use(authBasic.AuthMiddleware)
			r.Use(CORSHandler(route.Cors))
		}
	case JWTAuth:
		jwt, err := getJWTMiddleware(routeMiddleware.Rule)
		if err != nil {
			logger.Error("Error: %s", err.Error())
		} else {
			jwtAuth := middlewares.JwtAuth{
				Path:            route.Path,
				Paths:           routeMiddleware.Paths,
				AuthURL:         jwt.URL,
				RequiredHeaders: jwt.RequiredHeaders,
				Headers:         jwt.Headers,
				Params:          jwt.Params,
				Origins:         gateway.Cors.Origins,
			}
			// Apply JWT authentication middlewares
			r.Use(jwtAuth.AuthMiddleware)
			r.Use(CORSHandler(route.Cors))

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
				Path:         route.Path,
				Paths:        routeMiddleware.Paths,
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
				oauthRuler.RedirectPath = util.ParseRoutePath(route.Path, routeMiddleware.Paths[0])
			}
			if oauthRuler.Provider == "" {
				oauthRuler.Provider = "custom"
			}
			r.Use(amw.AuthMiddleware)
			r.Use(CORSHandler(route.Cors))
			r.HandleFunc(util.UrlParsePath(redirectURL), oauthRuler.callbackHandler).Methods("GET")
		}
	default:
		if !doesExist(routeMiddleware.Type) {
			logger.Error("Unknown middlewares type %s", routeMiddleware.Type)
		}

	}

}
