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
	gatewayName                          = "Goma Gateway"
	applicationJson                      = "application/json"
	CertsPath                            = ConfigDir + "certs"
	requestStartTimerKey      contextKey = "__requestStartTimer__"
	StatusClientClosedRequest            = 499
)

// ************** Middlewares types ***************
const (
	AccessMiddleware = "access" // access middlewares
	BasicAuth        = "basic"  // basic authentication middlewares
	JWTAuth          = "jwt"    // JWT authentication middlewares
	OAuth            = "oauth"  // OAuth authentication middlewares
	accessPolicy     = "accessPolicy"
	addPrefix        = "addPrefix"
	rateLimit        = "rateLimit"
	redirectRegex    = "redirectRegex"
	rewriteRegex     = "rewriteRegex"
	forwardAuth      = "forwardAuth"
	httpCache        = "httpCache"
	redirectScheme   = "redirectScheme"
	bodyLimit        = "bodyLimit"
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
