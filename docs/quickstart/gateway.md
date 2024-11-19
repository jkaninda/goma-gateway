---
title: Gateway
layout: default
parent: Quickstart
nav_order: 1
---

# Gateway

The Gateway serves as the entry point to the server. This section provides options to configure the proxy server, define routes, and specify additional routes. 

These settings enable precise control over traffic flow and routing within your deployment.

## Configuration Options

- **`sslCertFile`** (`string`): Path to the SSL certificate file.
- **`sslKeyFile`** (`string`): Path to the SSL certificate private key file.
- **`redis`**: Redis configuration settings.
- **`writeTimeout`** (`integer`): Timeout for writing responses (in seconds).
- **`readTimeout`** (`integer`): Timeout for reading requests (in seconds).
- **`idleTimeout`** (`integer`): Timeout for idle connections (in seconds).
- **`rateLimit`** (`integer`): Global rate limiting for the proxy.
- **`blockCommonExploits`** (`boolean`): Enable or disable blocking of common exploits.
- **`accessLog`** (`string`, default: `/dev/stdout`): Path for access logs.
- **`errorLog`** (`string`, default: `/dev/stderr`): Path for error logs.
- **`logLevel`** (`string`): Log verbosity level (e.g., `info`, `debug`, `error`).
- **`disableHealthCheckStatus`** (`boolean`): Enable or disable exposing the health check route status.
- **`disableRouteHealthCheckError`** (`boolean`): Enable or disable returning health check error responses for routes.
- **`disableDisplayRouteOnStart`** (`boolean`): Enable or disable displaying routes during server startup.
- **`disableKeepAlive`** (`boolean`): Enable or disable `keepAlive` for the proxy.
- **`enableMetrics`** (`boolean`): Enable or disable server metrics collection.
- **`interceptErrors`** (`array of integers`): List of HTTP status codes to intercept for custom handling.

### CORS Configuration

Customize Cross-Origin Resource Sharing (CORS) settings for the proxy:

- **`origins`** (`array of strings`): List of allowed origins.
- **`headers`** (`map[string]string`): Custom headers to include in responses.

### Additional Routes

Define custom routes for additional flexibility:

- **`directory`** (`string`): Directory path for serving extra routes.
- **`watch`** (`boolean`): Watch the directory for changes and update routes dynamically.

### Routes

Define the main routes for the Gateway, enabling routing logic for incoming requests.

---

## Example Configuration

```yaml
version: 1.0
gateway:
  sslCertFile: /etc/goma/cert.pem
  sslKeyFile: /etc/goma/key.pem
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  # Rate limiting
  rateLimit: 0
  accessLog: /dev/Stdout
  errorLog: /dev/stderr
  logLevel: info
  disableRouteHealthCheckError: false
  disableDisplayRouteOnStart: false
  disableKeepAlive: false
  disableHealthCheckStatus: false
  blockCommonExploits: true
  # Intercept backend errors
  interceptErrors:
    - 500
    - 405
  cors:
    origins:
      - http://localhost:8080
      - https://example.com
    headers:
      X-Custom-Header: "Value"
      Access-Control-Allow-Credentials: "true"
      Access-Control-Allow-Headers: Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id
      Access-Control-Max-Age: "1728000"
  ## Add additional routes
  extraRoutes:
    # path
    directory: /etc/goma/extra
    watch: true
  routes: []
```