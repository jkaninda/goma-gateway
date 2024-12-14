---
title: Error Interceptor
layout: default
parent: User Manual
nav_order: 5
---


## Error Interceptor

The Error Interceptor allows custom handling of backend error responses by intercepting specified HTTP status codes and returning customized response bodies.

### Configuration Options

- **`enabled`** (`boolean`): Determines whether the backend error interceptor is active.  
  *Default: `false*

- **`contentType`** (`string`): Specifies the `Content-Type` header of the response, such as `application/json` or `text/plain`.

- **`errors`** (`array`): A collection of error configurations defining which HTTP status codes to intercept and their corresponding custom responses.

### Error Configuration

Each entry in the `errors` array defines an individual error handling rule with the following properties:

- **`code`** (`integer`): The HTTP status code to intercept (e.g., `404`, `500`).
- **`body`** (`string`): The custom response body to return. This can be a plain string or a raw JSON string.

### Example of Route Error Interceptor

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
      errorInterceptor:
        enabled: true
        contentType: "application/json"
        errors:
          - code: 401
            body: ""
          - code: 404
            body: "{\"success\":false,\"code\":404,\"message\":\"Page not found\",\"data\":[]}" ## Raw JSON string     
          - code: 500
            body: "Internal server error"
      blockCommonExploits: false
      cors: {}
      ## Middleware
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```