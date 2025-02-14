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

package pkg

const ConfigDir = "/etc/goma/" // Default configuration file
const ExtraDir = ConfigDir + "extra"
const ConfigFile = "/etc/goma/goma.yml"                        // Default configuration file
const accessControlAllowOrigin = "Access-Control-Allow-Origin" // Cors
const gatewayName = "Goma Gateway"
const applicationJson = "application/json"
const CertsPath = ConfigDir + "certs"
const requestStartTimerKey contextKey = "__requestStartTimer__"
const StatusClientClosedRequest = 499

// Middlewares type
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

var (
	// Round-robin counter
	counter uint32
	// dynamicRoutes routes
	dynamicRoutes      []Route
	dynamicMiddlewares []Middleware
	redisBased         = false
	stopChan           = make(chan struct{})
	reloaded           = false
	webAddress         = ":8080"
	webSecureAddress   = ":8443"
)

type contextKey string
