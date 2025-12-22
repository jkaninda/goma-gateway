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
	"net/http"
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

func doesExist(tyName string) bool {
	// Convert input to MiddlewareType and compare
	return slices.Contains(buildInMiddlewares, tyName)
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
func loadExtraMiddlewares(path string) ([]Middleware, error) {
	yamlFiles, err := loadExtraFiles(path)
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
			return nil, fmt.Errorf("in file %q: %w", yamlFile, err)
		}
		extraMiddlewares = append(extraMiddlewares, ex.Middlewares...)

	}
	if len(extraMiddlewares) == 0 {
		logger.Debug(">>> No extra middleware found")
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
func (r *Route) applyMiddlewareByType(mid Middleware, router *mux.Router) {
	switch mid.Type {
	case AccessMiddleware:
		applyAccessMiddleware(mid, *r, router)
	case rateLimit, MiddlewareType(strings.ToLower(string(rateLimit))):
		applyRateLimitMiddleware(mid, *r, router)
	case accessPolicy:
		applyAccessPolicyMiddleware(mid, *r, router)
	case addPrefix:
		applyAddPrefixMiddleware(mid, router)
	case redirectRegex, rewriteRegex:
		applyRewriteRegexMiddleware(mid, router)
	case httpCache:
		applyHttpCacheMiddleware(*r, mid, router)
	case redirectScheme:
		applyRedirectSchemeMiddleware(mid, router)
	case bodyLimit:
		applyBodyLimitMiddleware(mid, router)
	case userAgentBlock:
		applyUserAgentBlockMiddleware(mid, router)
	case accessLog:
		applyAccessLogMiddleware(mid, r)
	case responseHeaders:
		applyResponseHeadersMiddleware(mid, r)
	case errorInterceptor:
		applyErrorInterceptorMiddleware(mid, r)
	}
	// Attach Auth middlewares
	attachAuthMiddlewares(*r, mid, router)
}

func applyErrorInterceptorMiddleware(mid Middleware, r *Route) {
	logger.Debug("Applying error interceptor middleware", "middleware", mid.Name, "route", r.Name)
	rule := &middlewares.RouteErrorInterceptor{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.Validate(); err != nil {
		logger.Error(fmt.Sprintf("Error: %v", err.Error()))
		return
	}
	r.errorInterceptor = rule

}
func applyAccessLogMiddleware(mid Middleware, r *Route) {
	logger.Debug("Applying access log middleware", "middleware", mid.Name, "route", r.Name)
	rule := &LogEnrichRule{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error(fmt.Sprintf("Error: %v", err.Error()))
		return
	}
	r.logRule = rule
}
func applyResponseHeadersMiddleware(mid Middleware, r *Route) {
	logger.Debug("Applying response headers middleware", "middleware", mid.Name, "route", r.Name)
	rule := &ResponseHeader{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error(fmt.Sprintf("Error: %v", err.Error()))
		return
	}
	rule.Name = mid.Name
	if len(mid.Paths) > 0 {
		rule.MatchedPath = mid.Paths[0]
		rule.Paths = mid.Paths
	}
	r.responseHeaders = append(r.responseHeaders, *rule)
}

func applyBodyLimitMiddleware(mid Middleware, r *mux.Router) {
	rule := &BodyLimitRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if len(rule.Limit) > 0 {
		maxBytes, err := goutils.ConvertToBytes(rule.Limit)
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
	var rule RedirectSchemeRuleMiddleware
	if err := goutils.DeepCopy(&rule, mid.Rule); err != nil {
		logger.Error("Failed to apply redirect scheme middleware: deep copy error", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Invalid redirect scheme middleware configuration", "error", err)
		return
	}
	redirect := &middlewares.RedirectScheme{
		Scheme:    rule.Scheme,
		Port:      rule.Port,
		Permanent: rule.Permanent,
	}

	r.Use(redirect.Middleware)
}

func applyHttpCacheMiddleware(route Route, mid Middleware, r *mux.Router) {
	rule := &httpCacheRule{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if rule.MaxTtl == 0 {
		rule.MaxTtl = 300
	}
	mLimit := int64(0)
	m, err := util.ConvertToBytes(rule.MemoryLimit)
	if err != nil {
		logger.Error("Error httpCaching memoryLimit", "error", err)
	}
	mLimit = m
	ttl := rule.MaxTtl * int64(time.Second)
	maxStale := rule.MaxStale * int64(time.Second)

	cache := middlewares.NewHttpCacheMiddleware(redisBased, time.Duration(ttl), mLimit)

	codes, err := util.ParseRanges(rule.ExcludedResponseCodes)
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
		DisableCacheStatusHeader: rule.DisableCacheStatusHeader,
		ExcludedResponseCodes:    codes,
	}
	r.Use(httpCacheM.Middleware)

}

func applyAccessMiddleware(mid Middleware, route Route, router *mux.Router) {
	rule := &AccessRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error applying middleware", "error", err.Error())
	}
	blM := middlewares.AccessListMiddleware{
		Path:       route.Path,
		Paths:      mid.Paths,
		Origins:    route.Cors.Origins,
		StatusCode: rule.StatusCode,
	}
	router.Use(blM.AccessMiddleware)
}

func applyRateLimitMiddleware(mid Middleware, route Route, router *mux.Router) {
	rule := &RateLimitRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error(fmt.Sprintf("Error: %v", err.Error()))
		return
	}
	duration, err := time.ParseDuration(rule.BanDuration)
	if err != nil {
		if rule.BanDuration != "" && rule.BanAfter != 0 {
			logger.Error("Error parsing banDuration in the rateLimit middleware, using default value", "name", mid.Name, "error", err)
		}
		duration = 10 * time.Minute
	}
	if rule.RequestsPerUnit != 0 {
		rt := middlewares.RateLimit{
			Unit:       rule.Unit,
			Path:       route.Path,
			Id:         util.Slug(route.Name),
			Requests:   rule.RequestsPerUnit,
			Origins:    route.Cors.Origins,
			Hosts:      route.Hosts,
			RedisBased: redisBased,
			PathBased:  len(mid.Paths) > 0,
			Paths:      mid.Paths,
			BanAfter:   rule.BanAfter,
			KeyStrategy: middlewares.RateLimitKeyStrategy{
				Source: rule.KeyStrategy.Source,
				Name:   rule.KeyStrategy.Name,
			},
			BanDuration: duration,
		}
		limiter := rt.NewRateLimiterWindow()
		router.Use(limiter.RateLimitMiddleware())
	}
}
func applyUserAgentBlockMiddleware(mid Middleware, router *mux.Router) {
	rule := &UserAgentBlockRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	userAgents := middlewares.UserAgentBlock{
		UserAgents: rule.UserAgents,
	}
	router.Use(userAgents.Middleware)
}

func applyAccessPolicyMiddleware(mid Middleware, route Route, router *mux.Router) {
	rule := &AccessPolicyRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}

	if len(rule.SourceRanges) > 0 {
		access := middlewares.AccessPolicy{
			SourceRanges: rule.SourceRanges,
			Action:       rule.Action,
			Origins:      route.Cors.Origins,
		}
		router.Use(access.AccessPolicyMiddleware)
	}
}

func applyAddPrefixMiddleware(mid Middleware, router *mux.Router) {
	rule := &AddPrefixRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	add := middlewares.AddPrefix{
		Prefix: rule.Prefix,
	}
	router.Use(add.AddPrefixMiddleware)
}
func applyRewriteRegexMiddleware(mid Middleware, router *mux.Router) {
	rule := &RewriteRegexRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	add := middlewares.RewriteRegex{
		Pattern:     rule.Pattern,
		Replacement: rule.Replacement,
	}
	router.Use(add.RewriteRegexMiddleware)
}

func attachAuthMiddlewares(route Route, routeMiddleware Middleware, r *mux.Router) {
	// Validate and apply middleware based on type
	switch routeMiddleware.Type {
	case BasicAuth, BasicAuthMiddleware:
		applyBasicAuthMiddleware(route, routeMiddleware, r)
	case LDAPAuthMiddleware, LDAPAuth:
		applyLdapAuthMiddleware(route, routeMiddleware, r)
	case JWTAuth, JWTAuthMiddleware:
		applyJWTAuthMiddleware(route, routeMiddleware, r)
	case forwardAuth:
		applyForwardAuthMiddleware(route, routeMiddleware, r)
	case OAuth, OAuth2:
		applyOAuthMiddleware(route, routeMiddleware, r)
	default:
		if !doesExist(string(routeMiddleware.Type)) {
			logger.Debug("Middleware type not found, skipping middleware application", "middleware", routeMiddleware.Name, "type", routeMiddleware.Type)
		}
	}
}

// applyBasicAuthMiddleware applies Basic Authentication middleware
func applyBasicAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	rule := &BasicRuleMiddleware{}
	if err := goutils.DeepCopy(rule, routeMiddleware.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}

	authBasic := &middlewares.AuthBasic{
		Path:            route.Path,
		Paths:           routeMiddleware.Paths,
		Realm:           rule.Realm,
		Users:           rule.Users,
		ForwardUsername: rule.ForwardUsername,
	}

	r.Use(authBasic.AuthMiddleware)
}

// applyLdapAuthMiddleware applies LDAP Authentication middleware
func applyLdapAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	rule := &LdapRuleMiddleware{}
	if err := goutils.DeepCopy(rule, routeMiddleware.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}

	basicAuth := &middlewares.AuthBasic{
		Path:            route.Path,
		Paths:           routeMiddleware.Paths,
		Realm:           rule.Realm,
		ForwardUsername: rule.ForwardUsername,
		Ldap: &middlewares.LDAP{
			URL:                rule.URL,
			BaseDN:             rule.BaseDN,
			BindDN:             rule.BindDN,
			BindPass:           rule.BindPass,
			UserFilter:         rule.UserFilter,
			StartTLS:           rule.StartTLS,
			InsecureSkipVerify: rule.InsecureSkipVerify,
		},
		ConnPoolBurst: rule.ConnPool.Burst,
		ConnPoolSize:  rule.ConnPool.Size,
		ConnPoolTTL:   rule.ConnPool.TTL,
	}
	r.Use(basicAuth.AuthMiddleware)
}

// applyJWTAuthMiddleware applies JWT Authentication middleware
func applyJWTAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	var err error
	rule := &JWTRuleMiddleware{}
	if err = goutils.DeepCopy(rule, routeMiddleware.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
		return
	}
	if err = rule.validate(); err != nil {
		logger.Error("Error validating JWT middleware, ", "error", err.Error())
		logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
		return
	}
	key := &rsa.PublicKey{}
	if rule.PublicKey != "" {
		key, err = loadRSAPublicKey(rule.PublicKey)
		if err != nil {
			logger.Error("Error JWT PublicKey", "error", err)
			logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
			return
		}
	}
	jwksFile := &middlewares.Jwks{}
	if rule.JwksFile != "" {
		jwksFile, err = loadJWKSFromFile(rule.JwksFile)
		if err != nil {
			logger.Error("Error JWT jwksFile", "error", err)
			logger.Warn("JWT middleware not applied to route", "middleware", routeMiddleware.Name, "route", route.Name, "reason", "missing or invalid configuration")
			return

		}
	}
	jwtAuth := &middlewares.JwtAuth{
		Path:                 route.Path,
		Paths:                routeMiddleware.Paths,
		ClaimsExpression:     rule.ClaimsExpression,
		ForwardHeaders:       rule.ForwardHeaders,
		ForwardAuthorization: rule.ForwardAuthorization,
		RsaKey:               key,
		Algo:                 rule.Alg,
		JwksFile:             jwksFile,
		Secret:               rule.Secret,
		JwksUrl:              rule.JwksUrl,
		Issuer:               rule.Issuer,
		Audience:             rule.Audience,
		Origins:              route.Cors.Origins,
	}

	r.Use(jwtAuth.AuthMiddleware)
}

// applyForwardAuthMiddleware applies Forward Authentication middleware
func applyForwardAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	rule := &ForwardAuthRuleMiddleware{}
	if err := goutils.DeepCopy(rule, routeMiddleware.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error validating middleware", "error", err)
		return
	}

	auth := &middlewares.ForwardAuth{
		AuthURL:                     rule.AuthURL,
		AuthSignIn:                  rule.AuthSignIn,
		ForwardHostHeaders:          rule.ForwardHostHeaders,
		InsecureSkipVerify:          rule.InsecureSkipVerify,
		AuthRequestHeaders:          rule.AuthRequestHeaders,
		AuthResponseHeaders:         rule.AuthResponseHeaders,
		AuthResponseHeadersAsParams: rule.AuthResponseHeadersAsParams,
		AddAuthCookiesToResponse:    rule.AddAuthCookiesToResponse,
		Path:                        route.Path,
		Paths:                       routeMiddleware.Paths,
		Origins:                     route.Cors.Origins,
	}

	r.Use(auth.AuthMiddleware)
}

// applyOAuthMiddleware applies OAuth Authentication middleware
func applyOAuthMiddleware(route Route, routeMiddleware Middleware, r *mux.Router) {
	rule := &OauthRulerMiddleware{}
	if err := goutils.DeepCopy(rule, routeMiddleware.Rule); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error validating middleware", "error", err)
		return
	}
	redirectPath := rule.RedirectPath
	redirectURL := "/callback" + route.Path
	cookiePath := rule.CookiePath
	if cookiePath == "" {
		cookiePath = route.Path
	}
	if rule.RedirectURL != "" {
		redirectURL = rule.RedirectURL
	}

	amw := middlewares.Oauth{
		Path:         route.Path,
		Paths:        routeMiddleware.Paths,
		ClientID:     rule.ClientID,
		ClientSecret: rule.ClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       rule.Scopes,
		Endpoint: middlewares.OauthEndpoint{
			AuthURL:     rule.Endpoint.AuthURL,
			TokenURL:    rule.Endpoint.TokenURL,
			UserInfoURL: rule.Endpoint.UserInfoURL,
			JwksURL:     rule.Endpoint.JwksURL,
		},
		State:      rule.State,
		Origins:    route.Cors.Origins,
		CookiePath: cookiePath,
		Provider:   rule.Provider,
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
	r.HandleFunc(util.UrlParsePath(redirectURL), oauthRuler.callbackHandler).Methods(http.MethodGet)
}
