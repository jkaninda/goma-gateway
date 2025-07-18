---
title: Error Interceptor
layout: default
parent: User Manual
nav_order: 5
---


## Error Interceptor

The **Error Interceptor** feature allows you to customize backend error responses by intercepting specific HTTP status codes and returning user-defined content. This is useful for presenting consistent and user-friendly error messages to clients.

---

### Configuration Options

* **`enabled`** (`boolean`): Enables or disables the error interceptor.
  *Default: \`false*

* **`contentType`** (`string`): The `Content-Type` of the response. Common values include:

  * `application/json`
  * `text/plain`

* **`errors`** (`[]ErrorMapping`): A list of error rules defining how specific HTTP status codes should be handled.

---

### Error Mapping Structure

Each entry in the `errors` array defines how to handle a specific HTTP status code:

* **`statusCode`** (`integer`): The HTTP status code to intercept (e.g., `401`, `404`, `500`).
* **`body`** (`string`): The custom response body. Can be a simple string or a raw JSON string.

---

### Example: Route with Error Interceptor

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      rewrite: /cart
      target: http://cart-service:8080
      methods: []
      healthCheck:
        path: "/health/live"
        interval: 10s
        timeout: 5s
        healthyStatuses: [200, 404]
      errorInterceptor:
        enabled: true
        contentType: "application/json"
        errors:
          - statusCode: 401
            body: ""  # Empty response body for 401 Unauthorized
          - statusCode: 404
            body: >
              {"success": false, "status": 404, "message": "Page not found", "data": []}
          - statusCode: 500
            body: "Internal server error"
      blockCommonExploits: false
      cors: {}
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

> ✅ Tip: Use `>` or `|` in YAML to handle multi-line or JSON strings cleanly.

---
