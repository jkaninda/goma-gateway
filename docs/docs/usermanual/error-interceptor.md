---
title: Error Interceptor
sidebar_label: Error Interceptor
sidebar_position: 5
---


## Error Interceptor

The **Error Interceptor** replaces a backend's error responses with content you
define, so clients see consistent messages whatever the upstream returns. It is
configured with the
[`errorInterceptor` middleware](../middlewares/error-interceptor.md) and applied
to the routes that need it.

:::warning[Removed in v1.0]

The `errorInterceptor` block on a route and on the gateway was removed in v1.0,
along with the `code` and `status` spellings of `statusCode`. A configuration
that still uses one will not start. See the
[v1.0 upgrade note](../upgrade/v1.0.md), or run `goma config check -c <file>` to
have the gateway point at them.

:::

---

### Configuration Options

* **`enabled`** (`boolean`): Enables or disables the error interceptor.
  *Default: `false`*

* **`contentType`** (`string`): The `Content-Type` of the response. Common values include:

  * `application/json`
  * `text/plain`
  * `text/html`
  * `application/xml`

* **`errors`** (`[]ErrorMapping`): A list of error rules defining how specific HTTP status codes should be handled.

---

### Error Mapping Structure

Each entry in the `errors` array defines how to handle a specific HTTP status code:

* **`statusCode`** (`integer`): The HTTP status code to intercept (e.g., `401`, `404`, `500`).
* **`body`** (`string`): The custom response body. Can be a simple string or a raw JSON string.
* **`file`** (`string`): A file to serve as the response body, instead of `body`.

---

### Example: Route with Error Interceptor

```yaml
version: 2
middlewares:
  - name: cart-errors
    type: errorInterceptor
    rule:
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
      middlewares: [cart-errors]
```

> ✅ Tip: Use `>` or `|` in YAML to handle multi-line or JSON strings cleanly.

Because the interceptor is a middleware, one definition can be shared by every
route that should return the same error bodies, and a route that needs different
ones simply names a different middleware.

---
