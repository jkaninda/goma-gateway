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
	"github.com/jkaninda/goma-gateway/pkg/copier"
	"github.com/jkaninda/goma-gateway/pkg/logger"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"sort"
	"strings"
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
	handleGatewayDeprecations(&gateway)
	dynamicRoutes = gateway.Routes
	dynamicMiddlewares = gatewayServer.middlewares
	// Load Extra Middlewares
	logger.Info("Loading additional configurations...")
	extraMiddlewares, err := loadExtraMiddlewares(gateway.ExtraConfig.Directory)
	if err == nil {
		dynamicMiddlewares = append(dynamicMiddlewares, extraMiddlewares...)
		logger.Info("Loaded %d additional middlewares", len(extraMiddlewares))

	}
	// Load Extra Routes
	extraRoutes, err := loadExtraRoutes(gateway.ExtraConfig.Directory)
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
	// Update Routes
	dynamicRoutes = validateRoutes(gateway, dynamicRoutes)

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
	if gateway.RateLimit > 0 {
		// Add rate limit middlewares to all routes, if defined
		rateLimit := middlewares.RateLimit{
			Id:         "global_rate",
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
	for _, route := range dynamicRoutes {

		// create route
		router := r.PathPrefix(route.Path).Subrouter()
		if len(route.Path) > 0 {
			if route.DisableHostForwarding {
				logger.Info("Route %s: host forwarding disabled ", route.Name)
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
			attachMiddlewares(route, gateway, router)
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
			if route.ErrorInterceptor.Enabled {
				interceptErrors := middlewares.InterceptErrors{
					Interceptor: route.ErrorInterceptor,
					Origins:     route.Cors.Origins,
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
	}

	return r

}

// attachMiddlewares attaches middlewares to the route
func attachMiddlewares(route Route, gateway Gateway, router *mux.Router) {
	if route.BlockCommonExploits {
		logger.Info("Block common exploits enabled")
		router.Use(middlewares.BlockExploitsMiddleware)
	}

	applyRateLimit(route, router)

	for _, middleware := range route.Middlewares {
		if len(middleware) == 0 {
			continue
		}

		mid, err := getMiddleware([]string{middleware}, dynamicMiddlewares)
		if err != nil {
			logger.Error("Error: %v", err.Error())
			continue
		}

		applyMiddlewareByType(mid, route, gateway, router)
	}
}

func applyRateLimit(route Route, router *mux.Router) {
	if route.RateLimit == 0 {
		return
	}

	rateLimit := middlewares.RateLimit{
		Unit:       "minute",
		Id:         util.Slug(route.Name),
		Requests:   route.RateLimit,
		Origins:    route.Cors.Origins,
		Hosts:      route.Hosts,
		RedisBased: redisBased,
	}
	limiter := rateLimit.NewRateLimiterWindow()
	router.Use(limiter.RateLimitMiddleware())
}

func applyMiddlewareByType(mid Middleware, route Route, gateway Gateway, router *mux.Router) {
	switch mid.Type {
	case AccessMiddleware:
		applyAccessMiddleware(mid, route, router)
	case rateLimit, strings.ToLower(rateLimit):
		applyRateLimitMiddleware(mid, route, router)
	case accessPolicy:
		applyAccessPolicyMiddleware(mid, route, router)
	case addPrefix:
		applyAddPrefixMiddleware(mid, router)
	case redirectRegex:
		applyRedirectRegexMiddleware(mid, router)

	}

	attachAuthMiddlewares(route, mid, gateway, router)
}

func applyAccessMiddleware(mid Middleware, route Route, router *mux.Router) {
	blM := middlewares.AccessListMiddleware{
		Path:    route.Path,
		List:    mid.Paths,
		Origins: route.Cors.Origins,
	}
	router.Use(blM.AccessMiddleware)
}

func applyRateLimitMiddleware(mid Middleware, route Route, router *mux.Router) {
	rateLimitMid := &RateLimitRuleMiddleware{}
	if err := copier.Copy(&mid.Rule, rateLimitMid); err != nil {
		logger.Error("Error: %v, middleware not applied", err.Error())
		return
	}
	if err := rateLimitMid.validate(); err != nil {
		logger.Error("Error: %v", err.Error())
		return
	}

	if rateLimitMid.RequestsPerUnit != 0 && route.RateLimit == 0 {
		rateLimit := middlewares.RateLimit{
			Unit:       rateLimitMid.Unit,
			Id:         util.Slug(route.Name),
			Requests:   rateLimitMid.RequestsPerUnit,
			Origins:    route.Cors.Origins,
			Hosts:      route.Hosts,
			RedisBased: redisBased,
			PathBased:  true,
			Paths:      util.AddPrefixPath(route.Path, mid.Paths),
		}
		limiter := rateLimit.NewRateLimiterWindow()
		router.Use(limiter.RateLimitMiddleware())
	}
}

func applyAccessPolicyMiddleware(mid Middleware, route Route, router *mux.Router) {
	a := &AccessPolicyRuleMiddleware{}
	if err := copier.Copy(&mid.Rule, a); err != nil {
		logger.Error("Error: %v, middleware not applied", err.Error())
		return
	}
	if err := a.validate(); err != nil {
		logger.Error("Error: %v, middleware not applied", err)
		return
	}

	if len(a.SourceRanges) > 0 {
		access := middlewares.AccessPolicy{
			SourceRanges: a.SourceRanges,
			Action:       a.Action,
			Origins:      route.Cors.Origins,
		}
		router.Use(access.AccessPolicyMiddleware)
	}
}

func applyAddPrefixMiddleware(mid Middleware, router *mux.Router) {
	a := AddPrefixRuleMiddleware{}
	if err := copier.Copy(&mid.Rule, &a); err != nil {
		logger.Error("Error: %v, middleware not applied", err.Error())
		return
	}
	add := middlewares.AddPrefix{
		Prefix: a.Prefix,
	}
	router.Use(add.AddPrefixMiddleware)
}
func applyRedirectRegexMiddleware(mid Middleware, router *mux.Router) {
	a := RedirectRegexRuleMiddleware{}
	if err := copier.Copy(&mid.Rule, &a); err != nil {
		logger.Error("Error: %v, middleware not applied", err.Error())
		return
	}
	add := middlewares.RedirectRegex{
		Pattern:     a.Pattern,
		Replacement: a.Replacement,
	}
	router.Use(add.RedirectRegexMiddleware)
}

func attachAuthMiddlewares(route Route, routeMiddleware Middleware, gateway Gateway, r *mux.Router) {
	// Check Authentication middleware types
	switch routeMiddleware.Type {
	case BasicAuth:
		basicAuth := BasicRuleMiddleware{}
		if err := copier.Copy(&routeMiddleware.Rule, &basicAuth); err != nil {
			logger.Error("Error: %v, middleware not applied", err.Error())
			return
		}
		err := basicAuth.validate()
		if err != nil {
			logger.Error("Error: %s", err.Error())
			return
		}
		authBasic := middlewares.AuthBasic{
			Path:     route.Path,
			Paths:    routeMiddleware.Paths,
			Users:    basicAuth.Users,
			Username: basicAuth.Username,
			Password: basicAuth.Password,
			Headers:  nil,
			Params:   nil,
		}

		// Apply JWT authentication middlewares
		r.Use(authBasic.AuthMiddleware)
		r.Use(CORSHandler(route.Cors))

	case JWTAuth:
		jwt := &JWTRuleMiddleware{}
		if err := copier.Copy(&routeMiddleware.Rule, jwt); err != nil {
			logger.Error("Error: %v, middleware not applied", err.Error())
			return
		}
		err := jwt.validate()
		if err != nil {
			logger.Error("Error: %s", err.Error())
			return
		}
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

	case OAuth:
		oauth := &OauthRulerMiddleware{}
		if err := copier.Copy(&routeMiddleware.Rule, oauth); err != nil {
			logger.Error("Error: %v, middleware not applied", err.Error())
			return
		}
		err := oauth.validate()
		if err != nil {
			logger.Error("Error: %s", err.Error())
			return
		}

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

	default:
		if !doesExist(routeMiddleware.Type) {
			logger.Error("Unknown middlewares type %s", routeMiddleware.Type)
		}

	}

}
