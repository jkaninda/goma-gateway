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

package internal

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/util"
	"gopkg.in/yaml.v3"
	"os"
	"slices"
	"strings"
	"time"
)

func getMiddleware(rules []string, middlewares []Middleware) (Middleware, error) {
	for _, m := range middlewares {
		if slices.Contains(rules, m.Name) {
			return m, nil
		}
		continue
	}

	return Middleware{}, errors.New("middleware not found with name:  [" + strings.Join(rules, ";") + "]")
}

func doesExist(tyName MiddlewareType) bool {
	middlewareList := []MiddlewareType{
		BasicAuth,
		JWTAuth,
		AccessMiddleware,
		accessPolicy,
		addPrefix,
		rateLimit,
		redirectRegex,
		forwardAuth,
		rewriteRegex,
		httpCache,
		redirectScheme,
		bodyLimit,
	}

	// Convert input to MiddlewareType and compare
	return slices.Contains(middlewareList, tyName)
}
func GetMiddleware(rule string, middlewares []Middleware) (Middleware, error) {
	for _, m := range middlewares {
		if strings.Contains(rule, m.Name) {

			return m, nil
		}
		continue
	}

	return Middleware{}, errors.New("no middlewares found with name " + rule)
}

// loadExtraMiddlewares loads additional middlewares
func loadExtraMiddlewares(routePath string) ([]Middleware, error) {
	yamlFiles, err := loadExtraFiles(routePath)
	if err != nil {
		return nil, fmt.Errorf("error loading extra files: %v", err)
	}
	var extraMiddlewares []Middleware
	for _, yamlFile := range yamlFiles {
		buf, err := os.ReadFile(yamlFile)
		if err != nil {
			return nil, fmt.Errorf("error loading extra file: %v", err)
		}
		ex := &ExtraMiddleware{}
		err = yaml.Unmarshal(buf, ex)
		if err != nil {
			return nil, fmt.Errorf("in file %q: %w", ConfigFile, err)
		}
		extraMiddlewares = append(extraMiddlewares, ex.Middlewares...)

	}
	if len(extraMiddlewares) == 0 {
		return nil, fmt.Errorf("no extra middleware found")
	}
	return extraMiddlewares, nil
}

// findDuplicateMiddlewareNames finds duplicated middleware name
func findDuplicateMiddlewareNames(middlewares []Middleware) ([]string, error) {
	// Create a map to track occurrences of names
	nameMap := make(map[string]int)
	var duplicates []string

	for _, mid := range middlewares {
		if mid.Name == "" {
			return duplicates, fmt.Errorf("name should not be empty")
		}
		nameMap[mid.Name]++
		// If the count is ==2, it's a duplicate
		if nameMap[mid.Name] == 2 {
			duplicates = append(duplicates, mid.Name)
		}
	}
	return duplicates, nil
}
func applyMiddlewareByType(mid Middleware, route Route, router *mux.Router) {
	switch mid.Type {
	case AccessMiddleware:
		applyAccessMiddleware(mid, route, router)
	case rateLimit, MiddlewareType(strings.ToLower(string(rateLimit))):
		applyRateLimitMiddleware(mid, route, router)
	case accessPolicy:
		applyAccessPolicyMiddleware(mid, route, router)
	case addPrefix:
		applyAddPrefixMiddleware(mid, router)
	case redirectRegex, rewriteRegex:
		applyRewriteRegexMiddleware(mid, router)
	case httpCache:
		applyHttpCacheMiddleware(route, mid, router)
	case redirectScheme:
		applyRedirectSchemeMiddleware(mid, router)
	case bodyLimit:
		applyBodyLimitMiddleware(mid, router)

	}
	// Attach Auth middlewares
	attachAuthMiddlewares(route, mid, router)
}

func applyBodyLimitMiddleware(mid Middleware, r *mux.Router) {
	bodyLimitMid := &BodyLimitRuleMiddleware{}
	if err := goutils.DeepCopy(bodyLimitMid, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if len(bodyLimitMid.Limit) > 0 {
		maxBytes, err := goutils.ConvertToBytes(bodyLimitMid.Limit)
		if err != nil {
			logger.Error("Error middleware not applied", "error", err)
		}
		if maxBytes > 0 {
			bodyLimitMiddleware := &middlewares.BodyLimit{MaxBytes: maxBytes}
			r.Use(bodyLimitMiddleware.Middleware)
		}
	}

}

func applyRedirectSchemeMiddleware(mid Middleware, r *mux.Router) {
	redirectSchemeMid := &RedirectSchemeRuleMiddleware{}
	if err := goutils.DeepCopy(redirectSchemeMid, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := redirectSchemeMid.validate(); err != nil {
		logger.Error("Error", "error", err)
		return
	}
	redirectSch := middlewares.RedirectScheme{
		Scheme:    redirectSchemeMid.Scheme,
		Port:      redirectSchemeMid.Port,
		Permanent: redirectSchemeMid.Permanent,
	}
	r.Use(redirectSch.Middleware)

}

func applyHttpCacheMiddleware(route Route, mid Middleware, r *mux.Router) {
	httpCacheMid := &httpCacheRule{}
	if err := goutils.DeepCopy(httpCacheMid, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if httpCacheMid.MaxTtl == 0 {
		httpCacheMid.MaxTtl = 300
	}
	mLimit := int64(0)
	m, err := util.ConvertToBytes(httpCacheMid.MemoryLimit)
	if err != nil {
		logger.Error("Error httpCaching memoryLimit", "error", err)
	}
	mLimit = m
	ttl := httpCacheMid.MaxTtl * int64(time.Second)
	maxStale := httpCacheMid.MaxStale * int64(time.Second)

	cache := middlewares.NewHttpCacheMiddleware(redisBased, time.Duration(ttl), mLimit)

	codes, err := util.ParseRanges(httpCacheMid.ExcludedResponseCodes)
	if err != nil {
		logger.Error("Error HttpCacheConfig excludedResponseCodes", "error", err)
	}
	httpCacheM := middlewares.HttpCacheConfig{
		Path:                     route.Path,
		Name:                     util.Slug(route.Name),
		Paths:                    mid.Paths,
		Cache:                    cache,
		Origins:                  route.Cors.Origins,
		TTL:                      time.Duration(ttl),
		MaxStale:                 time.Duration(maxStale),
		RedisBased:               redisBased,
		DisableCacheStatusHeader: httpCacheMid.DisableCacheStatusHeader,
		ExcludedResponseCodes:    codes,
	}
	r.Use(httpCacheM.Middleware)

}

func applyAccessMiddleware(mid Middleware, route Route, router *mux.Router) {
	accessM := &AccessRuleMiddleware{}
	if err := goutils.DeepCopy(accessM, mid.Rule); err != nil {
		logger.Error("Error applying middleware", "error", err.Error())
	}
	blM := middlewares.AccessListMiddleware{
		Path:       route.Path,
		Paths:      mid.Paths,
		Origins:    route.Cors.Origins,
		StatusCode: accessM.StatusCode,
	}
	router.Use(blM.AccessMiddleware)
}

func applyRateLimitMiddleware(mid Middleware, route Route, router *mux.Router) {
	rateLimitMid := &RateLimitRuleMiddleware{}
	if err := goutils.DeepCopy(rateLimitMid, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rateLimitMid.validate(); err != nil {
		logger.Error(fmt.Sprintf("Error: %v", err.Error()))
		return
	}

	if rateLimitMid.RequestsPerUnit != 0 && route.RateLimit == 0 {
		rt := middlewares.RateLimit{
			Unit:       rateLimitMid.Unit,
			Id:         util.Slug(route.Name),
			Requests:   rateLimitMid.RequestsPerUnit,
			Origins:    route.Cors.Origins,
			Hosts:      route.Hosts,
			RedisBased: redisBased,
			PathBased:  true,
			Paths:      util.AddPrefixPath(route.Path, mid.Paths),
		}
		limiter := rt.NewRateLimiterWindow()
		router.Use(limiter.RateLimitMiddleware())
	}
}

func applyAccessPolicyMiddleware(mid Middleware, route Route, router *mux.Router) {
	a := &AccessPolicyRuleMiddleware{}
	if err := goutils.DeepCopy(a, mid.Rule); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	if err := a.validate(); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
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
	a := &AddPrefixRuleMiddleware{}
	if err := goutils.DeepCopy(a, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	add := middlewares.AddPrefix{
		Prefix: a.Prefix,
	}
	router.Use(add.AddPrefixMiddleware)
}
func applyRewriteRegexMiddleware(mid Middleware, router *mux.Router) {
	a := &RewriteRegexRuleMiddleware{}
	if err := goutils.DeepCopy(a, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	add := middlewares.RewriteRegex{
		Pattern:     a.Pattern,
		Replacement: a.Replacement,
	}
	router.Use(add.RewriteRegexMiddleware)
}

func attachAuthMiddlewares(route Route, routeMiddleware Middleware, r *mux.Router) {
	// Validate and apply middleware based on type
	switch routeMiddleware.Type {
	case BasicAuth, BasicAuthMiddleware:
		applyBasicAuthMiddleware(route, routeMiddleware, r)
	case JWTAuth, JWTAuthMiddleware:
		applyJWTAuthMiddleware(route, routeMiddleware, r)
	case forwardAuth:
		applyForwardAuthMiddleware(route, routeMiddleware, r)
	case OAuth, OAuth2:
		applyOAuthMiddleware(route, routeMiddleware, r)
	default:
		if !doesExist(routeMiddleware.Type) {
			logger.Error("Unknown middleware type, ", "type", routeMiddleware.Type)
		}
	}
}

// applyBasicAuthMiddleware applies Basic Authentication middleware
func applyBasicAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	basicAuth := &BasicRuleMiddleware{}
	if err := goutils.DeepCopy(basicAuth, routeMiddleware.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := basicAuth.validate(); err != nil {
		logger.Error("Error", "error", err)
		return
	}

	authBasic := middlewares.AuthBasic{
		Path:     route.Path,
		Paths:    routeMiddleware.Paths,
		Realm:    basicAuth.Realm,
		Users:    basicAuth.Users,
		Username: basicAuth.Username,
		Password: basicAuth.Password,
		Headers:  nil,
		Params:   nil,
	}

	r.Use(authBasic.AuthMiddleware)
	r.Use(CORSHandler(route.Cors))
}

// applyJWTAuthMiddleware applies JWT Authentication middleware
func applyJWTAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	var err error
	jwt := &JWTRuleMiddleware{}
	if err = goutils.DeepCopy(jwt, routeMiddleware.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
		return
	}
	if err = jwt.validate(); err != nil {
		logger.Error("Error validating JWT middleware, ", "error", err.Error())
		logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
		return
	}
	key := &rsa.PublicKey{}
	if jwt.PublicKey != "" {
		key, err = loadRSAPublicKey(jwt.PublicKey)
		if err != nil {
			logger.Error("Error JWT PublicKey", "error", err)
			logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
			return
		}
	}
	jwksFile := &middlewares.Jwks{}
	if jwt.JwksFile != "" {
		jwksFile, err = loadJWKSFromFile(jwt.JwksFile)
		if err != nil {
			logger.Error("Error JWT jwksFile", "error", err)
			logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
			return

		}
	}
	jwtAuth := middlewares.JwtAuth{
		Path:                 route.Path,
		Paths:                routeMiddleware.Paths,
		Claims:               jwt.Claims,
		ForwardHeaders:       jwt.ForwardHeaders,
		ForwardAuthorization: jwt.ForwardAuthorization,
		RsaKey:               key,
		Algo:                 jwt.Alg,
		JwksFile:             jwksFile,
		Secret:               jwt.Secret,
		JwksUrl:              jwt.JwksUrl,
		Issuer:               jwt.Issuer,
		Audience:             jwt.Audience,
		Origins:              route.Cors.Origins,
	}

	r.Use(jwtAuth.AuthMiddleware)
	r.Use(CORSHandler(route.Cors))
}

// applyForwardAuthMiddleware applies Forward Authentication middleware
func applyForwardAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	fAuth := &ForwardAuthRuleMiddleware{}
	if err := goutils.DeepCopy(fAuth, routeMiddleware.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := fAuth.validate(); err != nil {
		logger.Error("Error validating middleware", "error", err)
		return
	}

	auth := middlewares.ForwardAuth{
		AuthURL:                     fAuth.AuthURL,
		AuthSignIn:                  fAuth.AuthSignIn,
		EnableHostForwarding:        fAuth.EnableHostForwarding,
		SkipInsecureVerify:          fAuth.SkipInsecureVerify,
		AuthRequestHeaders:          fAuth.AuthRequestHeaders,
		AuthResponseHeaders:         fAuth.AuthResponseHeaders,
		AuthResponseHeadersAsParams: fAuth.AuthResponseHeadersAsParams,
		AddAuthCookiesToResponse:    fAuth.AddAuthCookiesToResponse,
		Path:                        route.Path,
		Paths:                       routeMiddleware.Paths,
		Origins:                     route.Cors.Origins,
	}

	r.Use(auth.AuthMiddleware)
	r.Use(CORSHandler(route.Cors))
}

// applyOAuthMiddleware applies OAuth Authentication middleware
func applyOAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	oauth := &OauthRulerMiddleware{}
	if err := goutils.DeepCopy(oauth, routeMiddleware.Rule); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	if err := oauth.validate(); err != nil {
		logger.Error("Error validating middleware", "error", err)
		return
	}
	redirectPath := oauth.RedirectPath
	redirectURL := "/callback" + route.Path
	cookiePath := oauth.CookiePath
	if cookiePath == "" {
		cookiePath = route.Path
	}
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
			JwksURL:     oauth.Endpoint.JwksURL,
		},
		State:      oauth.State,
		Origins:    route.Cors.Origins,
		CookiePath: cookiePath,
		Provider:   oauth.Provider,
	}

	oauthRuler := oauthRulerMiddleware(amw)
	oauthRuler.RedirectPath = redirectPath
	oauthRuler.CookiePath = cookiePath
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
