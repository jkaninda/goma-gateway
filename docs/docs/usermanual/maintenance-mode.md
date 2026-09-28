---
title: Maintenance Mode
sidebar_label: Maintenance Mode
sidebar_position: 11
---

# Maintenance Mode

Goma Gateway provides a **maintenance mode** feature that allows you to temporarily block access to your backend services. This is useful during:

* Planned maintenance windows
* Service upgrades or deployments
* Emergency downtime or troubleshooting

Maintenance mode is set per route. When it is enabled, Goma Gateway answers every request on that route with a configurable HTTP status code and message instead of forwarding it to the backend. The check runs before the route's middlewares, so no authentication or other middleware is evaluated.

---

## Configuration Fields

* **`enabled`** (`boolean`, default: `false`)
  Whether maintenance mode is active.

    * `true` → Maintenance mode enabled (all requests blocked).
    * `false` → Maintenance mode disabled (requests routed normally).

* **`statusCode`** (`integer`, optional, default: `503`)
  The HTTP status code returned when maintenance mode is active.

    * Common values:

        * `503` → Service Unavailable (default)
        * `500` → Internal Server Error
        * `404` → Not Found (useful if you want the service to appear absent)

* **`message`** (`string`, optional)
  The response body to send when maintenance mode is active.

    * Defaults to: `"503 Service temporarily unavailable"`.
    * The response format is chosen from the request's `Accept` header (or `Content-Type` when `Accept` is absent): a value of exactly `application/json` returns `{"success": false, "statusCode": ..., "error": "<message>"}` (or the message itself if it is valid JSON), `application/xml` or `text/xml` returns an XML document, and anything else returns plain text.

---

## Example: Maintenance Mode Configuration

```yaml
gateway:
  routes:
    - name: api-example
      path: /
      target: http://api-example:8080
      maintenance:
        enabled: true
        statusCode: 503
        message: "503 Service Unavailable"
```

Maintenance mode is part of the route configuration, so it can be switched on and off with a configuration reload, without restarting the gateway.
