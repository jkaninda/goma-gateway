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

- **`tlsCertFile`** (`string`): Path to the TLS certificate file.
- **`tlsKeyFile`** (`string`): Path to the TLS certificate private key file.
- **`redis`**: Redis configuration settings.
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
version: 1.0
gateway:
  tlsCertFile: /etc/goma/cert.pem
  tlsKeyFile: /etc/goma/key.pem
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  accessLog: /dev/Stdout
  errorLog: /dev/stderr
  logLevel: info
  disableRouteHealthCheckError: false
  disableDisplayRouteOnStart: false
  disableKeepAlive: false
  disableHealthCheckStatus: false
  blockCommonExploits: false
  errorInterceptor:
      enabled: true
      contentType: "application/json"
      errors:
        - status: 401
          body: ""
        - status: 500
          body: "Internal server error"
  cors:
    origins:
      - http://localhost:8080
      - https://example.com
    headers:
      X-Custom-Header: "Value"
      Access-Control-Allow-Credentials: "true"
      Access-Control-Allow-Headers: Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id
      Access-Control-Max-Age: "1728000"
  ## extra config for additional configuration files (e.g., routes and middleware).
  extraConfig:
    # path
    directory: /etc/goma/extra
    watch: true
  routes: []
```