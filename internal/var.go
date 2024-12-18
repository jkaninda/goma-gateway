package internal

const ConfigDir = "/etc/goma/" // Default configuration file
const ExtraDir = ConfigDir + "extra"
const ConfigFile = "/etc/goma/goma.yml"                        // Default configuration file
const accessControlAllowOrigin = "Access-Control-Allow-Origin" // Cors
const gatewayName = "Goma Gateway"
const applicationJson = "application/json"

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
)

var (
	// Round-robin counter
	counter uint32
	// dynamicRoutes routes
	dynamicRoutes      []Route
	dynamicMiddlewares []Middleware
	redisBased         = false
)
