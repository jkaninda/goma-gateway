---
title: Gateway
layout: default
parent: User Manual
nav_order: 1
---

# Gateway

The Gateway serves as the entry point to the server. This section provides options to configure the proxy server, define routes, and specify additional routes. 

These settings enable precise control over traffic flow and routing within your deployment.

## Configuration Options

- **`redis`**: Redis configuration settings.
- **`tls`**: Global TLS configuration .
- **`writeTimeout`** (`integer`): Timeout for writing responses (in seconds).
- **`readTimeout`** (`integer`): Timeout for reading requests (in seconds).
- **`idleTimeout`** (`integer`): Timeout for idle connections (in seconds).
- **`blockCommonExploits`** (`boolean`): Enable or disable blocking of common exploits.
- **`accessLog`** (`string`, default: `/dev/stdout`): Path for access logs.
- **`errorLog`** (`string`, default: `/dev/stderr`): Path for error logs.
- **`logLevel`** (`string`): Log verbosity level (e.g., `info`, `debug`, `error`).
- **`disableHealthCheckStatus`** (`boolean`): Enable or disable exposing the health check route status.
- **`disableRouteHealthCheckError`** (`boolean`): Enable or disable returning health check error responses for routes.
- **`disableDisplayRouteOnStart`** (`boolean`): Enable or disable displaying routes during server startup.
- **`disableKeepAlive`** (`boolean`): Enable or disable `keepAlive` for the proxy.
- **`enableMetrics`** (`boolean`): Enable or disable server metrics collection.


## TLS Configuration

Goma Gateway allows you to define global TLS certificates for securing routes.

These certificates are used to encrypt traffic between clients and the gateway.

#### Keys Configuration

You can define a list of TLS certificates for the routes using the following keys:

- **`cert`** (`string`):  
  Specifies the TLS certificate. This can be provided as:
  - A file path to the certificate.
  - Raw certificate content.
  - A base64-encoded certificate.

- **`key`** (`string`):  
  Specifies the private key corresponding to the TLS certificate. 
   
  This can be provided as:
  - A file path to the private key.
  - Raw private key content.
  - A base64-encoded private key.

---
### CORS Configuration

Customize Cross-Origin Resource Sharing (CORS) settings for the proxy:

- **`origins`** (`array of strings`): List of allowed origins.
- **`headers`** (`map[string]string`): Custom headers to include in responses.

### Error Interceptor
- **`enabled`** (`boolean`): Determines whether the backend error interceptor is active.  
  *Default: `false`*
- **`contentType`** (`string`): Specifies the `Content-Type` header of the response, such as `application/json` or `text/plain`.
- **`errors`** (`array`): A collection of error configurations defining which HTTP status codes to intercept and their corresponding custom responses.

### Extra Config

Define custom routes and middlewares for greater flexibility:

- **`directory`** (`string`): The directory path where additional route and middleware configuration files are stored.
- **`watch`** (`boolean`): Watch the directory for changes and update routes dynamically.

### Routes

Define the main routes for the Gateway, enabling routing logic for incoming requests.

---

## Example Configuration

```yaml
version: 2  # Configuration version
gateway:
  # Timeout settings for the gateway
  writeTimeout: 15  # Maximum time (in seconds) to wait for a write operation to complete
  readTimeout: 15   # Maximum time (in seconds) to wait for a read operation to complete
  idleTimeout: 30   # Maximum idle time (in seconds) before closing an inactive connection

  # TLS configuration for securing the gateway
  tls:
    keys:  # List of TLS certificates and private keys
      - cert: /etc/goma/cert.pem  # File path to the TLS certificate
        key: /etc/goma/key.pem    # File path to the private key
      - cert: |  # Raw certificate content (PEM format)
          -----BEGIN CERTIFICATE-----
        key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...  # Base64-encoded private key

  # Logging configuration
  accessLog: /dev/Stdout  # File path or output stream for access logs
  errorLog: /dev/stderr   # File path or output stream for error logs
  logLevel: info          # Logging level (e.g., info, debug, warn, error)

  # Gateway behavior settings
  disableRouteHealthCheckError: false  # Enable/disable health check error logging
  disableDisplayRouteOnStart: false    # Enable/disable displaying routes on startup
  disableKeepAlive: false              # Enable/disable keep-alive connections
  disableHealthCheckStatus: false      # Enable/disable health check status updates
  blockCommonExploits: false           # Enable/disable blocking common web exploits

  # Error interceptor configuration
  errorInterceptor:
    enabled: true  # Enable/disable error interception
    contentType: "application/json"  # Content type for error responses
    errors:  # Custom error responses for specific HTTP status codes
      - status: 401  # Unauthorized
        body: ""     # Empty response body
      - status: 500  # Internal Server Error
        body: "Internal server error"  # Custom error message

  # CORS (Cross-Origin Resource Sharing) configuration
  cors:
    origins:  # Allowed origins for CORS
      - http://localhost:8080
      - https://example.com
    headers:  # Custom headers for CORS
      X-Custom-Header: "Value"  # Example custom header
      Access-Control-Allow-Credentials: "true"  # Allow credentials (e.g., cookies)
      Access-Control-Allow-Headers: Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id  # Allowed headers
      Access-Control-Max-Age: "1728000"  # Max age for preflight requests (in seconds)

  # Extra configuration for additional files (e.g., routes and middleware)
  extraConfig:
    directory: /etc/goma/extra  # Directory path for additional configuration files
    watch: true  # Enable/disable watching the directory for changes

  # Routes configuration (empty in this example)
  routes: []  # Define routes for the gateway (e.g., path, backends, health checks)
```

---
### Notes

- Ensure that the `cert` and `key` values are correctly formatted and match each other. Mismatched certificates and keys will result in TLS handshake failures.
- If using file paths, ensure the gateway has read access to the specified files.
- For raw or base64-encoded content, ensure there are no formatting errors or extra spaces.
- TLS configuration is global and applies to all routes unless overridden by route-specific configurations.
