---
title: Route
layout: default
parent: User Manual
nav_order: 2
---


# Route

A **Route** defines how incoming HTTP traffic is matched and forwarded to backend services. It supports path and host matching, request rewriting, CORS, method filtering, health checks, load balancing, middleware, and more.

---

## Configuration Options

Below are the configuration options for defining routes in Goma Gateway:

### Basic Route Options

* **`path`** (`string`): Path to match (e.g., `/api/v1/resource`).
* **`name`** (`string`): Unique name for the route.
* **`enabled`** (`boolean`): Enables or disables the route. If set to `false`, the route will not be proxied.
* **`hosts`** (`[]string`): Optional list of allowed hostnames.
* **`rewrite`** (`string`): Rewrites the request path before forwarding.

  > For advanced rewriting (regex-based), consider using the `rewriteRegex` middleware.
* **`methods`** (`[]string`): Allowed HTTP methods (e.g., `GET`, `POST`). Defaults to all if omitted.
* **`target`** (`string`): Single backend target (overridden if `backends` is set).
* **`backends`** (`[]Backend`): List of backend endpoints for load balancing.
* **`security`**: Per-route security configuration.
* **`tls`**: Per-route TLS settings.
* **`priority`** (`int`): Optional priority for route matching. Lower values take precedence.

---

## Health Check Configuration

Configure periodic health checks for route backends:

```yaml
healthCheck:
  path: "/health"
  interval: 30s      # Default: 30s
  timeout: 10s       # Default: 10s
  healthyStatuses: [200, 404]
```

* **`path`** (`string`): URL path used for health checks.
* **`interval`** (`duration`): How frequently to check.
* **`timeout`** (`duration`): Timeout for the health check request.
* **`healthyStatuses`** (`[]int`): List of HTTP status codes considered healthy.

---

## Security Configuration

Control forwarding behavior and backend TLS validation:

```yaml
security:
  forwardHostHeaders: true
  enableExploitProtection: false
  tls:
    skipVerification: false
    rootCAs: /etc/goma/certs/root.ca.pem
```

* **`forwardHostHeaders`** (`bool`, default: `true`): Whether to forward the original `Host` header.
* **`enableExploitProtection`** (`bool`, default: `false`): Enable built-in protections against known exploits.
* **`tls.skipVerification`** (`bool`, default: `false`): Disable TLS certificate verification for backend.
* **`tls.rootCAs`**: Custom root CA (file path, raw PEM, or base64-encoded string).

---

## CORS Configuration

The `cors` section allows you to control Cross-Origin Resource Sharing behavior for each route. This is essential for enabling secure cross-origin requests from web applications.

Configure per-route CORS settings:

### Configuration Fields

```yaml
cors:
  origins:
    - http://localhost:3000
    - https://dev.example.com
  allowedHeaders:
    - Origin
    - Authorization
  headers: {}              # Custom response headers (as key-value pairs)
  exposeHeaders: []        # Headers exposed to the browser
  maxAge: 1728000          # Preflight cache duration in seconds
  allowMethods: []         # Allowed HTTP methods (empty means all methods allowed)
  allowCredentials: true   # Whether to allow cookies or credentials
```

* **`origins`** (`[]string`): List of allowed origins. Requests from these domains are permitted.
* **`allowedHeaders`** (`[]string`): Headers allowed in CORS preflight requests.
* **`headers`** (`map[string]string`): Custom headers to be added to the response.
* **`exposeHeaders`** (`[]string`): Headers that are safe to expose to the browser.
* **`maxAge`** (`int`): Duration (in seconds) to cache the results of a preflight request.
* **`allowMethods`** (`[]string`): Allowed HTTP methods (e.g., `GET`, `POST`). If empty, all methods are allowed.
* **`allowCredentials`** (`boolean`): Allows browsers to send cookies and credentials along with requests.
* **`middlewares`** (`[]string`): List of middleware names to apply to the route.

---

## Error Interceptor

Handle specific backend response codes gracefully:

```yaml
errorInterceptor:
  enabled: true
  contentType: "application/json"
  errors:
    - code: 401
      body: ""
    - code: 500
      body: "Internal server error"
```

* **`enabled`** (`boolean`): Enable error interception.
* **`contentType`** (`string`): Content-Type header for the response (e.g., `application/json`).
* **`errors`** (`[]ErrorResponse`): List of error overrides with status codes and custom response bodies.


---

## Route Priority

* If no route has a `priority` defined, routes are matched by longest path.
* If `priority` is set, lower numbers take precedence during matching.

---

## Minimal Route Configuration

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /cart
      target: http://cart-service:8080
```

---

## Example: Route with Security

```yaml
version: 2
gateway:
  routes:
    - name: cart
      path: /cart
      rewrite: /
      target: http://cart-service:8080
      security:
        forwardHostHeaders: true
        enableExploitProtection: true
        tls:
          skipVerification: true
          rootCAs: /etc/goma/certs/root.ca.pem
```

---

## Example: Limited HTTP Methods

```yaml
version: 2
gateway:
  routes:
    - name: Example
      enabled: false
      path: /store/cart
      target: http://cart-service:8080
      methods: [PATCH, GET]
      cors: {}
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

---

## Example: Route with Health Check

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      backends:
        - endpoint: http://cart-service:8080
      methods: [PATCH, GET]
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200, 404]
      cors: {}
```

---

## Example: Route with Middleware

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      backends:
        - endpoint: http://cart-service:8080
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200, 404]
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

---

## Example: Route with Error Interceptor

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      backends:
        - endpoint: http://cart-service:8080
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200, 404]
      errorInterceptor:
        enabled: true
        contentType: "application/json"
        errors:
          - code: 401
            body: ""
          - code: 500
            body: "Internal server error"
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

---

## Example: Route with Load Balancing

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: example route
      hosts:
        - example.com
        - example.localhost
      rewrite: /
      healthCheck:
        path: /
        interval: 30s
        timeout: 10s
        healthyStatuses: [200, 404]
      backends:
        - endpoint: https://example.com
          weight: 1
        - endpoint: https://example1.com
          weight: 3
        - endpoint: https://example2.com
          weight: 2
      cors: {}
```