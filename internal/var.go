package pkg

const ConfigDir = "/etc/goma/"                                 // Default configuration file
const ConfigFile = "/etc/goma/goma.yml"                        // Default configuration file
const accessControlAllowOrigin = "Access-Control-Allow-Origin" // Cors
const serverName = "Goma"
const gatewayName = "Goma Gateway"
const AccessMiddleware = "access" // access middleware
const BasicAuth = "basic"         // basic authentication middleware
const JWTAuth = "jwt"             // JWT authentication middleware
const OAuth = "oauth"             // OAuth authentication middleware
// Round-robin counter
var counter uint32
