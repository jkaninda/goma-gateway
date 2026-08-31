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

const (
	ConfigDir                           = "/etc/goma/" // Default configuration file
	ExtraDir                            = ConfigDir + "extra"
	ConfigFile                          = "/etc/goma/goma.yml"          // Default configuration file
	accessControlAllowOrigin            = "Access-Control-Allow-Origin" // Cors
	GatewayName                         = "Goma Gateway"
	applicationJson                     = "application/json"
	CertsPath                           = ConfigDir + "certs"
	CtxRequestStartTime      contextKey = "requestStartTime"
	CtxRequestIDHeader       contextKey = "requestID"
	CtxSelectedBackend       contextKey = "selectedBackend"
	RequestIDHeader                     = "X-Goma-Request-ID"
	GomaAccessToken                     = "goma_access_token"
	GomaRefreshToken                    = "goma_refresh_token"
	GomaIDToken                         = "goma_id_token"

	// SameSite cookie attribute values, as written in the configuration.
	sameSiteStrict            = "strict"
	sameSiteLax               = "lax"
	sameSiteNone              = "none"
	StatusClientClosedRequest = 499
	acmeServerURL             = "127.0.0.1:5002"
	visitorPrefix             = "visitor-"
)

// ************** Built-In Middlewares types ***************
const (
	AccessMiddleware    MiddlewareType = "access"    // access middlewares
	BasicAuthMiddleware MiddlewareType = "basic"     // basic authentication middlewares
	BasicAuth           MiddlewareType = "basicAuth" // basic authentication middlewares
	JWTAuthMiddleware   MiddlewareType = "jwt"       // JWT authentication middlewares
	LDAPAuthMiddleware  MiddlewareType = "ldapAuth"  // JWT authentication middlewares
	LDAPAuth            MiddlewareType = "ldap"      // JWT authentication middlewares
	JWTAuth             MiddlewareType = "jwtAuth"   // JWT authentication middlewares
	OIDC                MiddlewareType = "oidc"      // OpenID Connect authentication middlewares
	OAuth               MiddlewareType = "oauth"     // Deprecated: use oidc
	OAuth2              MiddlewareType = "oauth2"    // Deprecated: use oidc
	accessPolicy        MiddlewareType = "accessPolicy"
	addPrefix           MiddlewareType = "addPrefix"
	rateLimit           MiddlewareType = "rateLimit"
	rewriteRegex        MiddlewareType = "rewriteRegex"
	forwardAuth         MiddlewareType = "forwardAuth"
	httpCache           MiddlewareType = "httpCache"
	redirectScheme      MiddlewareType = "redirectScheme"
	redirectRegex       MiddlewareType = "redirectRegex"
	redirect            MiddlewareType = "redirect"
	bodyLimit           MiddlewareType = "bodyLimit"
	userAgentBlock      MiddlewareType = "userAgentBlock"
	accessLog           MiddlewareType = "accessLog"
	responseHeaders     MiddlewareType = "responseHeaders"
	requestHeaders      MiddlewareType = "requestHeaders"
	errorInterceptor    MiddlewareType = "errorInterceptor"
	geoBlock            MiddlewareType = "geoBlock"
	stripQuery          MiddlewareType = "stripQuery"
)

// ************** CORS ***************
const (
	AccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	AccessControlAllowHeaders     = "Access-Control-Allow-headers"
	AccessControlExposeHeaders    = "Access-Control-Expose-headers"
	AccessControlAllowMethods     = "Access-Control-Allow-Methods"
	AccessControlMaxAge           = "Access-Control-Max-Age"
	AccessControlAllowCredentials = "Access-Control-Allow-Credentials"
)

// ************** SourceType *****************
const (
	SourceTypeHeader SourceType = "header"
	SourceTypeCookie SourceType = "cookie"
	SourceTypeQuery  SourceType = "query"
	SourceTypeIp     SourceType = "ip"
)

// ************** OperatorType *****************

const (
	OperatorEquals      OperatorType = "equals"
	OperatorNotEquals   OperatorType = "not_equals"
	OperatorContains    OperatorType = "contains"
	OperatorNotContains OperatorType = "not_contains"
	OperatorStartsWith  OperatorType = "starts_with"
	OperatorEndsWith    OperatorType = "ends_with"
	OperatorRegex       OperatorType = "regex"
	OperatorIn          OperatorType = "in"
)
const (
	constHTTPProtocol  = "http"
	constHTTPSProtocol = "https"
	constJsonExt       = ".json"
	constYamlExt       = ".yaml"
	constYmlExt        = ".yml"
	constYaml          = "yaml"
	constJson          = "json"
)

// ************** Server hardening defaults *****************
const (
	// defaultServerTimeout is the fallback for gateway.timeouts.{read,write,idle},
	// in seconds. Zero means "unlimited" to net/http, which is not a safe default.
	defaultServerTimeout = 60
	// defaultReadHeaderTimeout bounds how long a client may take to send its
	// request headers. Always applied, independent of gateway.timeouts.
	defaultReadHeaderTimeout = 10
	// defaultMaxHeaderBytes caps the request header size at 1 MiB.
	defaultMaxHeaderBytes = 1 << 20
)

// defaultCacheMemoryLimit is the fallback for httpCache.memoryLimit: 64 MiB.
const defaultCacheMemoryLimit = 64 << 20

// blockAccessMiddlewareName is the access middleware `goma config init`
// scaffolds, referenced by name from the routes it guards.
const blockAccessMiddlewareName = "block-access"
