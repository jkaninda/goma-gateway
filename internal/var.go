package internal

const ConfigDir = "/etc/goma/" // Default configuration file
const ExtraDir = ConfigDir + "extra"
const ConfigFile = "/etc/goma/goma.yml"                        // Default configuration file
const accessControlAllowOrigin = "Access-Control-Allow-Origin" // Cors
const gatewayName = "Goma Gateway"
const applicationJson = "application/json"
const CertsPath = ConfigDir + "/certs"

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
)
