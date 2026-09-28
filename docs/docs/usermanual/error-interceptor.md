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

* **`contentType`** (`string`): How `body` is returned. When empty, the client's `Accept` header (or `Content-Type`) is used instead.

  * `application/json`: a `body` that is valid JSON is returned as is; any other text is wrapped as `{"success": false, "statusCode": <code>, "error": "<body>"}`.
  * `application/xml` or `text/xml`: the body is wrapped in an XML `<error>` document.
  * Anything else (for example `text/plain`): the body is returned as plain text.

* **`errors`** (`[]ErrorMapping`): A list of error rules defining how specific HTTP status codes should be handled. At least one entry is required.

---

### Error Mapping Structure

Each entry in the `errors` array defines how to handle a specific HTTP status code:

* **`statusCode`** (`integer`): The HTTP status code to intercept (e.g., `401`, `404`, `500`).
* **`body`** (`string`): The custom response body. Can be a simple string or a raw JSON string. When neither `body` nor `file` is set, the body is `<code> <reason>`, for example `404 Not Found`.
* **`file`** (`string`): Path to an HTML file served as the response body (`text/html`). Used only when `body` is empty.

The original status code is kept; only the body and `Content-Type` are replaced.

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
        - statusCode: 401  # No body: the default "401 Unauthorized" message is used
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
ones simply names a different middleware. A route uses a single error
interceptor: if it lists several, only the last one applies.

---
