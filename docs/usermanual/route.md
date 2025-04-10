---
title: Route
layout: default
parent: User Manual
nav_order: 2
---


# Route

The Route allows you to match on HTTP traffic and direct it to the backend.


## Configuration Options

This section outlines the available configuration options for defining routes in the Gateway.

### Route Configuration

- **`path`** (`string`): The route path (e.g., `/api/v1/resource`).
- **`name`** (`string`): A unique name for the route.
- **`disabled`** (`boolean`): Disabled specifies whether the route is disabled, the route will not be proxied.
- **`hosts`** (`list of strings`): A list of allowed hostnames for the route.
- **`rewrite`** (`string`): Updates the incoming route path to a specified new path.
   - For more advanced use cases involving pattern matching or regular expressions, consider using the `rewriteRegex` middleware instead.
- **`methods`** (`array of strings`): A list of allowed HTTP methods (e.g., `GET`, `POST`).
- **`destination`** (`string`): The backend endpoint for the route.
- **`backends`** (`list of strings`): A list of backend services for load balancing.
- **`insecureSkipVerify`** (`boolean`): Disables backend TLS certificate verification.
- **`tls`**: Route TLS configuration .
- **`priority`**  (`integer`): Determines route matching order


## Health Check Configuration

- **`healthCheck`**:
    - **`path`** (`string`): The health check path (e.g., `/health`).
    - **`interval`** (`string`, default: `30s`): The interval between health checks.
    - **`timeout`** (`string`, default: `10s`): The maximum time to wait for a health check response.
    - **`healthyStatuses`** (`array of integers`): A list of HTTP status codes considered healthy.

## CORS Configuration

- **`cors`**:
    - **`origins`** (`array of strings`): A list of allowed origins for Cross-Origin Resource Sharing (CORS).
    - **`headers`** (`array of strings`): A list of custom headers to include in responses.

## Error Interceptor
- **`enabled`** (`boolean`): Determines whether the backend error interceptor is active.  
  *Default: `false`*
- **`contentType`** (`string`): Specifies the `Content-Type` header of the response, such as `application/json` or `text/plain`.
- **`errors`** (`array`): A collection of error configurations defining which HTTP status codes to intercept and their corresponding custom responses.


---
## Additional Options

- **`disableHostForwarding`** (`boolean`): Disables proxy host forwarding for improved security.
- **`blockCommonExploits`** (`boolean`): Enables or disables blocking of common exploits.
- **`enableBotDetection`** (`boolean`): Enables or disables bot detection, protect route from bots by blocking requests from known bots.
- **`middlewares`** (`array of strings`): A list of middleware names applied to the route.


## Route priority

- If no route has a positive priority, routes are matched in descending order based on their path.
- If at least one route has a positive priority, routes are matched in ascending order based on priority values (lower numbers take precedence).

---
### ### Minimal Configuration

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart # You can use RewriteRegex middleware for more complex rewrites
      destination: http://cart-service:8080
```

###  Route with limited HTTP methods
The proxy will allow all HTTP methods if there's no defined method.

Example of route with limited HTTP methods allowed for a particular route.

```yaml
version: 2
gateway:
  ...
  routes:
    - name: Example
      disabled: false # Disabled specifies whether the route is disabled, the route will not be proxied.
      path: /store/cart
      destination: http://cart-service:8080
      methods: [PATCH, GET]
      cors: {}
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

### Route with healthcheck

Example of route with backend health check.

```yaml
version: 2
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      backends:
        - endpoint:  http://cart-service:8080
      methods: [PATCH, GET]
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200,404]
      cors: {}
```
### Route with middleware

Example of route with backend health check.

```yaml
version: 2
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      backends:
        - endpoint:  http://cart-service:8080
      methods: []
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200,404]
      cors: {}
      ## Middleware
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```
### Route with backend errors interceptor

Example of route with backend errors interceptor.

```yaml
version: 2
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      backends:
        - endpoint:  http://cart-service:8080
      methods: []
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200,404]
      errorInterceptor:
        enabled: true
        contentType: "application/json"
        errors:
          - code: 401
            body: ""
          - code: 500
            body: "Internal server error"
      blockCommonExploits: false
      cors: {}
      ## Middleware
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```
### Route with enabled load balancing

Example of route with load balancing enabled.

Below is an example configuration for weighted load balancing:


```yaml
version: 2  # Configuration version
gateway:
  routes:
    - path: /  # The path to match for this route
      name: example route  # A descriptive name for the route
      hosts:  # List of hostnames this route will handle
        - example.com
        - example.localhost
      rewrite: /  # Rewrite the incoming request path (if needed)
      methods: []  # HTTP methods to allow (empty means all methods are allowed)
      healthCheck:  # Health check configuration for backend servers
        path: "/"  # Endpoint to check for health
        interval: 30s  # Time interval between health checks
        timeout: 10s  # Timeout for health check requests
        healthyStatuses: [200, 404]  # HTTP status codes considered healthy
      ## destination: will be overridden by backends
      destination: ""  # Placeholder for backend destination (overridden by `backends`)
      backends:  # List of backend servers for load balancing
        - endpoint: https://example.com  # Backend server URL
          weight: 1
        - endpoint: https://example1.com  # Backend server URL
          weight: 3
        - endpoint: https://example2.com  # Backend server URL
          weight: 2
      cors: {}
```