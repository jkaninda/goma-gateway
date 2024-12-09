package pkg

const ConfigDir = "/etc/goma/" // Default configuration file
const ExtraDir = ConfigDir + "extra"
const ConfigFile = "/etc/goma/goma.yml"                        // Default configuration file
const accessControlAllowOrigin = "Access-Control-Allow-Origin" // Cors
const gatewayName = "Goma Gateway"
const AccessMiddleware = "access" // access middlewares
const BasicAuth = "basic"         // basic authentication middlewares
const JWTAuth = "jwt"             // JWT authentication middlewares
const OAuth = "oauth"             // OAuth authentication middlewares
const accessPolicy = "accessPolicy"

var (
	// Round-robin counter
	counter uint32
	// dynamicRoutes routes
	dynamicRoutes       []Route
	dynamicMiddlewares  []Middleware
	RateLimitMiddleware = []string{"ratelimit", "rateLimit"} // Rate Limit middlewares
	redisBased          = false
)
