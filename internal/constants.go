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
	ConfigDir                            = "/etc/goma/" // Default configuration file
	ExtraDir                             = ConfigDir + "extra"
	ConfigFile                           = "/etc/goma/goma.yml"          // Default configuration file
	accessControlAllowOrigin             = "Access-Control-Allow-Origin" // Cors
	GatewayName                          = "Goma Gateway"
	applicationJson                      = "application/json"
	CertsPath                            = ConfigDir + "certs"
	CtxRequestStartTime       contextKey = "requestStartTime"
	CtxRequestIDHeader        contextKey = "requestID"
	CtxSelectedBackend        contextKey = "selectedBackend"
	RequestIDHeader                      = "X-Goma-Request-ID"
	GomaAccessToken                      = "goma_access_token"
	GomaRefreshToken                     = "goma_refresh_token"
	StatusClientClosedRequest            = 499
	acmeServerURL                        = "localhost:5002"
)

// ************** Middlewares types ***************
const (
	AccessMiddleware    MiddlewareType = "access"    // access middlewares
	BasicAuthMiddleware MiddlewareType = "basic"     // basic authentication middlewares
	BasicAuth           MiddlewareType = "basicAuth" // basic authentication middlewares
	JWTAuthMiddleware   MiddlewareType = "jwt"       // JWT authentication middlewares
	LDAPAuthMiddleware  MiddlewareType = "ldapAuth"  // JWT authentication middlewares
	LDAPAuth            MiddlewareType = "ldap"      // JWT authentication middlewares
	JWTAuth             MiddlewareType = "jwtAuth"   // JWT authentication middlewares
	OAuth               MiddlewareType = "oauth"     // OAuth authentication middlewares
	OAuth2              MiddlewareType = "oauth2"    // OAuth authentication middlewares
	accessPolicy        MiddlewareType = "accessPolicy"
	addPrefix           MiddlewareType = "addPrefix"
	rateLimit           MiddlewareType = "rateLimit"
	redirectRegex       MiddlewareType = "redirectRegex"
	rewriteRegex        MiddlewareType = "rewriteRegex"
	forwardAuth         MiddlewareType = "forwardAuth"
	httpCache           MiddlewareType = "httpCache"
	redirectScheme      MiddlewareType = "redirectScheme"
	bodyLimit           MiddlewareType = "bodyLimit"
)
const (
	ProtocolTCP    Protocol = "tcp"
	ProtocolUDP    Protocol = "udp"
	ProtocolTCPUDP Protocol = "tcp/udp"
)

// ************** CORS ***************
const (
	AccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	AccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	AccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	AccessControlAllowMethods     = "Access-Control-Allow-Methods"
	AccessControlMaxAge           = "Access-Control-Max-Age"
	AccessControlAllowCredentials = "Access-Control-Allow-Credentials"
)
