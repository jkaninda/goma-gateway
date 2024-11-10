---
title: Route
layout: default
parent: Quickstart
nav_order: 2
---


# Route

The Route allows you to match on HTTP traffic and direct it to the backend.

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