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
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	goutils "github.com/jkaninda/go-utils"
	"github.com/jkaninda/goma-gateway/internal/middlewares"
	"github.com/jkaninda/goma-gateway/util"
	"github.com/jkaninda/njia"
	"gopkg.in/yaml.v3"
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
		buf, err := readConfigFile(yamlFile)
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
func (r *Route) applyMiddlewareByType(mid Middleware, router *njia.Group) {
	switch mid.Type {
	case AccessMiddleware:
		applyAccessMiddleware(mid, *r, router)
	case rateLimit, MiddlewareType(strings.ToLower(string(rateLimit))):
		applyRateLimitMiddleware(mid, *r, router)
	case accessPolicy:
		applyAccessPolicyMiddleware(mid, *r, router)
	case addPrefix:
		applyAddPrefixMiddleware(mid, router)
	case redirect:
		applyRedirectMiddleware(mid, router)
	case redirectScheme:
		applyRedirectSchemeMiddleware(mid, router)
	case rewriteRegex:
		applyRewriteRegexMiddleware(mid, router)
	case stripQuery:
		applyStripQueryMiddleware(mid, router)
	case redirectRegex:
		applyRedirectRegexMiddleware(mid, router)
	case httpCache:
		applyHttpCacheMiddleware(*r, mid, router)
	case bodyLimit:
		applyBodyLimitMiddleware(mid, router)
	case userAgentBlock:
		applyUserAgentBlockMiddleware(mid, router)
	case geoBlock:
		applyGeoBlockMiddleware(mid, router)
	case accessLog:
		applyAccessLogMiddleware(mid, r)
	case responseHeaders:
		applyResponseHeadersMiddleware(mid, r)
	case requestHeaders:
		applyRequestHeadersMiddleware(mid, *r, router)
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
func applyRequestHeadersMiddleware(mid Middleware, route Route, router *njia.Group) {
	logger.Debug("Applying request headers middleware", "middleware", mid.Name, "route", route.Name)
	rule := &RequestHeader{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Request headers middleware not applied", "middleware", mid.Name, "error", err)
		return
	}
	if len(rule.SetHeaders) == 0 && len(rule.RemoveHeaders) == 0 {
		logger.Debug("Request headers middleware has no setHeaders or removeHeaders, skipping",
			"middleware", mid.Name, "route", route.Name)
		return
	}
	rh := &middlewares.RequestHeaders{
		Path:          route.Path,
		Paths:         mid.Paths,
		SetHeaders:    rule.SetHeaders,
		RemoveHeaders: rule.RemoveHeaders,
	}
	router.Use(rh.Middleware)
}

func applyResponseHeadersMiddleware(mid Middleware, r *Route) {
	logger.Debug("Applying response headers middleware", "middleware", mid.Name, "route", r.Name)
	rule := &ResponseHeader{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if err := rule.validate(r); err != nil {
		logger.Error("Response headers middleware not applied", "middleware", mid.Name, "route", r.Name, " error", err)
		return
	}
	rule.Name = mid.Name
	if len(mid.Paths) > 0 {
		rule.MatchedPath = mid.Paths[0]
		rule.Paths = mid.Paths
	}
	r.responseHeaders = append(r.responseHeaders, *rule)
}

func applyBodyLimitMiddleware(mid Middleware, r *njia.Group) {
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

func applyRedirectSchemeMiddleware(mid Middleware, r *njia.Group) {
	var rule RedirectSchemeRuleMiddleware
	if err := goutils.DeepCopy(&rule, mid.Rule); err != nil {
		logger.Error("Failed to apply redirect scheme middleware: deep copy error", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Invalid redirect scheme middleware configuration", "error", err)
		return
	}
	redirectSchemeM := &middlewares.RedirectScheme{
		Scheme:    rule.Scheme,
		Port:      rule.Port,
		Permanent: rule.Permanent,
	}
	r.Use(redirectSchemeM.Middleware)
}
func applyRedirectMiddleware(mid Middleware, r *njia.Group) {
	var rule RedirectRuleMiddleware
	if err := goutils.DeepCopy(&rule, mid.Rule); err != nil {
		logger.Error("Failed to apply redirect scheme middleware: deep copy error", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Invalid redirect scheme middleware configuration", "error", err)
		return
	}
	redirectSchemeM := &middlewares.Redirect{
		URL:       rule.Url,
		Permanent: rule.Permanent,
	}
	r.Use(redirectSchemeM.Middleware)
}
func applyRedirectRegexMiddleware(mid Middleware, r *njia.Group) {
	var rule RedirectRegexRuleMiddleware
	if err := goutils.DeepCopy(&rule, mid.Rule); err != nil {
		logger.Error("Failed to apply redirect scheme middleware: deep copy error", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Invalid redirectRegex  middleware configuration", "error", err)
		return
	}
	redirectSchemeM := &middlewares.RedirectRegex{
		Pattern:     rule.Pattern,
		Replacement: rule.Replacement,
		Permanent:   rule.Permanent,
	}
	r.Use(redirectSchemeM.Middleware)
}

func applyHttpCacheMiddleware(route Route, mid Middleware, r *njia.Group) {
	rule := &httpCacheRule{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if rule.MaxTtl == 0 {
		rule.MaxTtl = 300
	}
	mLimit := int64(0)
	m, err := goutils.ConvertToBytes(rule.MemoryLimit)
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
		Name:                     goutils.Slug(route.Name),
		Paths:                    mid.Paths,
		Cache:                    cache,
		Origins:                  route.Cors.Origins,
		TTL:                      time.Duration(ttl),
		MaxStale:                 time.Duration(maxStale),
		RedisBased:               redisBased,
		DisableCacheStatusHeader: rule.DisableCacheStatusHeader,
		ExcludedResponseCodes:    codes,
		CacheableStatusCodes:     rule.CacheableStatusCodes,
		IncludeQueryInKey:        rule.IncludeQueryInKey,
		QueryParamsToCache:       rule.QueryParamsToCache,
		CachePrivateResponses:    rule.CachePrivateResponses,
		IgnoreVary:               rule.IgnoreVary,
	}
	r.Use(httpCacheM.Middleware)

}

func applyAccessMiddleware(mid Middleware, route Route, router *njia.Group) {
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

func applyRateLimitMiddleware(mid Middleware, route Route, router *njia.Group) {
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
			Id:         goutils.Slug(route.Name),
			Requests:   rule.RequestsPerUnit,
			Burst:      rule.Burst,
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
func applyUserAgentBlockMiddleware(mid Middleware, router *njia.Group) {
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

func applyGeoBlockMiddleware(mid Middleware, router *njia.Group) {
	rule := &GeoBlockRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	countries := make(map[string]struct{}, len(rule.Countries))
	for _, c := range rule.Countries {
		countries[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}
	allowUnknown := true // fail-open: an absent/unreadable GeoIP DB never locks everyone out
	if rule.AllowUnknown != nil {
		allowUnknown = *rule.AllowUnknown
	}
	geo := middlewares.GeoBlock{
		Name:          mid.Name,
		Deny:          strings.EqualFold(rule.Action, "DENY"),
		Countries:     countries,
		StatusCode:    rule.StatusCode,
		Message:       rule.Message,
		AllowUnknown:  allowUnknown,
		CountryHeader: rule.AddCountryHeader,
		Resolve:       geoCountry,
		OnDeny: func(country string) {
			prometheusMetrics.GatewayGeoBlockDenied.WithLabelValues(mid.Name, country).Inc()
		},
	}
	router.Use(geo.Middleware)
}

func applyAccessPolicyMiddleware(mid Middleware, route Route, router *njia.Group) {
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

func applyAddPrefixMiddleware(mid Middleware, router *njia.Group) {
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
func applyRewriteRegexMiddleware(mid Middleware, router *njia.Group) {
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

// applyStripQueryMiddleware removes optional query parameters the gateway will
// not forward, instead of refusing the request that carries them.
func applyStripQueryMiddleware(mid Middleware, router *njia.Group) {
	rule := &StripQueryRuleMiddleware{}
	if err := goutils.DeepCopy(rule, mid.Rule); err != nil {
		logger.Error("Error middleware not applied", "error", err)
		return
	}
	if len(rule.Params) == 0 {
		logger.Error("Error middleware not applied: stripQuery requires at least one param", "middleware", mid.Name)
		return
	}
	if rule.PathPattern != "" {
		if _, err := regexp.Compile(rule.PathPattern); err != nil {
			logger.Error("Error middleware not applied: invalid stripQuery pathPattern", "middleware", mid.Name, "error", err)
			return
		}
	}
	add := middlewares.StripQuery{
		Params:      rule.Params,
		Methods:     rule.Methods,
		PathPattern: rule.PathPattern,
	}
	router.Use(add.StripQueryMiddleware)
}

func attachAuthMiddlewares(route Route, routeMiddleware Middleware, r *njia.Group) {
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
	case OAuth, OAuth2, OIDC:
		applyOIDCMiddleware(route, routeMiddleware, r)
	default:
		if !doesExist(string(routeMiddleware.Type)) {
			logger.Debug("Middleware type not found, skipping middleware application", "middleware", routeMiddleware.Name, "type", routeMiddleware.Type)
		}
	}
}

// applyBasicAuthMiddleware applies Basic Authentication middleware
func applyBasicAuthMiddleware(route Route, routeMiddleware Middleware, r *njia.Group) {
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
func applyLdapAuthMiddleware(route Route, routeMiddleware Middleware, r *njia.Group) {
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
func applyJWTAuthMiddleware(route Route, routeMiddleware Middleware, r *njia.Group) {
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
		Forward:              claimMapper(rule.Forward, rule.ForwardHeaders),
		ForwardAuthorization: rule.ForwardAuthorization,
		RsaKey:               key,
		Algo:                 rule.Alg,
		Algorithms:           rule.Algorithms,
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
func applyForwardAuthMiddleware(route Route, routeMiddleware Middleware, r *njia.Group) {
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

// applyOIDCMiddleware applies OpenID Connect authentication to a route: the
// middleware guards the configured paths, and the login callback and logout
// endpoints are registered inside the route's group.
func applyOIDCMiddleware(route Route, routeMiddleware Middleware, r *njia.Group) {
	rule := &OIDCRuleMiddleware{}
	if err := goutils.DeepCopy(rule, routeMiddleware.Rule); err != nil {
		logger.Error("Error applying middleware, middleware not applied", "error", err)
		return
	}
	if err := rule.validate(); err != nil {
		logger.Error("Error validating middleware", "error", err)
		return
	}

	callbackPath := rule.CallbackPath
	if callbackPath == "" {
		callbackPath = util.ParseURLPath(route.Path + "/oauth2/callback")
	}

	sessionOpts := sessionOptions(rule.Session, route.Path)
	// The browser must send the session and login cookies to the middleware's
	// own endpoints, or the flow it started can never be completed.
	warnUnreachableEndpoint(routeMiddleware.Name, "callbackPath", callbackPath, sessionOpts.CookiePath)
	if rule.LogoutPath != "" {
		warnUnreachableEndpoint(routeMiddleware.Name, "logoutPath", rule.LogoutPath, sessionOpts.CookiePath)
	}

	config := middlewares.OIDCConfig{
		Path:         route.Path,
		Paths:        routeMiddleware.Paths,
		Origins:      route.Cors.Origins,
		ClientID:     rule.ClientID,
		ClientSecret: rule.ClientSecret,
		Provider:     rule.Provider,
		Issuer:       rule.Issuer,
		Audience:     rule.Audience,
		Scopes:       rule.Scopes,
		Endpoint: middlewares.OauthEndpoint{
			AuthURL:     rule.Endpoint.AuthURL,
			TokenURL:    rule.Endpoint.TokenURL,
			UserInfoURL: rule.Endpoint.UserInfoURL,
			JwksURL:     rule.Endpoint.JwksURL,
		},
		RedirectURL:        rule.RedirectURL,
		CallbackPath:       callbackPath,
		LogoutPath:         rule.LogoutPath,
		PostLoginRedirect:  rule.PostLoginRedirect,
		PostLogoutRedirect: rule.PostLogoutRedirect,
		DisablePKCE:        rule.PKCE != nil && !*rule.PKCE,
		ClaimsSource:       rule.ClaimsSource,
		ClaimsExpression:   rule.ClaimsExpression,
		Forward:            claimMapper(rule.Forward, nil),
		Session:            sessionOpts,
	}

	oidc, err := middlewares.NewOIDC(config)
	if err != nil {
		logger.Error("Error applying middleware, middleware not applied",
			"middleware", routeMiddleware.Name, "route", route.Name, "error", err)
		return
	}

	r.Use(oidc.AuthMiddleware)

	// The callback and logout endpoints live inside the route's group, so their
	// exact paths outrank the route's catch-all. The route stays guarded even if
	// they cannot be registered: an unprotected route would be worse than a
	// login that fails loudly.
	registerOIDCEndpoint(r, route, "callback", callbackPath, oidc.CallbackHandler)
	if rule.LogoutPath != "" {
		registerOIDCEndpoint(r, route, "logout", rule.LogoutPath, oidc.LogoutHandler)
	}
}

// registerOIDCEndpoint registers one of the middleware's own endpoints at an
// absolute request path.
func registerOIDCEndpoint(r *njia.Group, route Route, name, path string, handler http.HandlerFunc) {
	pattern, ok := groupPattern(route.Path, path)
	if !ok {
		logger.Error("The OIDC "+name+" path must be under the route path, login cannot complete",
			"route", route.Name, "routePath", route.Path, "path", path)
		return
	}
	if err := r.Handle(http.MethodGet, pattern, handler); err != nil {
		logger.Error("Failed to register the OIDC "+name+" endpoint",
			"route", route.Name, "path", path, "error", err)
	}
}

// groupPattern turns an absolute request path into the pattern to register on a
// route's group, which joins its own prefix onto whatever it is given.
func groupPattern(routePath, absolutePath string) (string, bool) {
	prefix := groupPrefix(routePath)
	switch {
	case prefix == "":
		return absolutePath, true
	case absolutePath == prefix:
		return "/", true
	case strings.HasPrefix(absolutePath, prefix+"/"):
		return strings.TrimPrefix(absolutePath, prefix), true
	default:
		return "", false
	}
}

// warnUnreachableEndpoint reports an endpoint the session cookie would not be
// sent to, which silently breaks the login or logout it serves.
func warnUnreachableEndpoint(middlewareName, field, path, cookiePath string) {
	if cookiePath == "" || cookiePath == "/" {
		return
	}
	if path == cookiePath || strings.HasPrefix(path, strings.TrimSuffix(cookiePath, "/")+"/") {
		return
	}
	logger.Warn("The OIDC "+field+" is outside the session cookie path, the browser will not send the session to it",
		"middleware", middlewareName, field, path, "session.cookie.path", cookiePath)
}

// sessionOptions turns the session rule into the middleware's options, scoping
// the cookie to the route when the operator has not chosen a path.
func sessionOptions(rule *OIDCSessionRule, routePath string) middlewares.SessionOptions {
	options := middlewares.SessionOptions{CookiePath: routePath}
	if rule == nil {
		return options
	}

	options.Store = rule.Store
	options.Secret = rule.Secret
	options.CookieName = rule.Cookie.Name
	options.CookieDomain = rule.Cookie.Domain
	options.CookieSecure = rule.Cookie.Secure
	if rule.Cookie.Path != "" {
		options.CookiePath = rule.Cookie.Path
	}
	// Durations are validated when the rule is loaded.
	if rule.TTL != "" {
		options.TTL, _ = time.ParseDuration(rule.TTL)
	}
	if rule.IdleTimeout != "" {
		options.IdleTimeout, _ = time.ParseDuration(rule.IdleTimeout)
	}
	switch strings.ToLower(rule.Cookie.SameSite) {
	case sameSiteStrict:
		options.SameSite = http.SameSiteStrictMode
	case sameSiteNone:
		options.SameSite = http.SameSiteNoneMode
	default:
		options.SameSite = http.SameSiteLaxMode
	}
	return options
}
