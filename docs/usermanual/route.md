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
- **`hosts`** (`list of strings`): A list of allowed hostnames for the route.
- **`rewrite`** (`string`): Rewrites the incoming route path to a new path.
- **`methods`** (`array of strings`): A list of allowed HTTP methods (e.g., `GET`, `POST`).
- **`destination`** (`string`): The backend endpoint for the route.
- **`backends`** (`list of strings`): A list of backend services for load balancing.
- **`insecureSkipVerify`** (`boolean`): Disables backend TLS certificate verification.

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

## Additional Options

- **`rateLimit`** (`integer`): The maximum number of requests allowed per minute.
- **`disableHostForwarding`** (`boolean`): Disables proxy host forwarding for improved security.
- **`interceptErrors`** (`array of integers`): A list of backend error status codes to intercept for custom handling.
- **`blockCommonExploits`** (`boolean`): Enables or disables blocking of common exploits.
- **`middlewares`** (`array of strings`): A list of middleware names applied to the route.

---

### Simple route

```yaml
version: 1.0
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      destination:  http://cart-service:8080
      cors: {}
```
###  Route with limited HTTP methods
The proxy will allow all HTTP methods if there's no defined method.

Example of route with limited HTTP methods allowed for a particular route.

```yaml
version: 1.0
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      destination:  http://cart-service:8080
      methods: [PATCH, GET]
      cors: {}
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

### Route with healthcheck

Example of route with backend health check.

```yaml
version: 1.0
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      destination:  http://cart-service:8080
      methods: [PATCH, GET]
      healthCheck:
        path: "/health/live"
        interval: 0
        timeout: 0
        healthyStatuses: [200,404]
      cors: {}
```
### Route with middleware

Example of route with backend health check.

```yaml
version: 1.0
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      destination:  http://cart-service:8080
      methods: []
      healthCheck:
        path: "/health/live"
        interval: 0
        timeout: 0
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
version: 1.0
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      destination:  http://cart-service:8080
      methods: []
      healthCheck:
        path: "/health/live"
        interval: 0
        timeout: 0
        healthyStatuses: [200,404]
      interceptErrors: [403,500]
      blockCommonExploits: false
      cors: {}
      ## Middleware
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```
### Route with enabled load balancing

Example of route with load balancing enabled.

```yaml
version: 1.0
gateway:
  ...
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      ## destination: will be override by backends
      destination: ""
      backends:
          - https://example.com
          - https://example2.com
          - https://example4.com
      insecureSkipVerify: true
      methods: []
      healthCheck:
        path: "/health/live"
        interval: 0
        timeout: 0
        healthyStatuses: [200,404]
      interceptErrors: [403,500]
      blockCommonExploits: false
      cors: {}
      ## Middleware
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```