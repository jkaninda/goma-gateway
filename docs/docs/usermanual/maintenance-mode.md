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

* **`html`** (`string`, optional)
  An HTML page served to browsers while maintenance mode is active.

    * Used when the request's `Accept` header contains `text/html`, as every browser's does. The page is sent as-is with `Content-Type: text/html; charset=utf-8` and the configured `statusCode`.
    * Other clients, such as API calls asking for `application/json`, still get `message` in the format described above.
    * Keep the page self-contained (inline CSS, no assets served from the route itself), since every request to the route is answered with it.
    * Gateways older than this field log it as an unknown key and serve `message` instead.

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

## Example: An HTML Page for Browsers

```yaml
gateway:
  routes:
    - name: web
      path: /
      target: http://web:8080
      maintenance:
        enabled: true
        message: "We're upgrading. Back at 14:00 UTC."
        html: |
          <!doctype html>
          <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Back soon</title>
            <style>
              body { font-family: system-ui, sans-serif; display: grid; place-items: center; min-height: 100vh; margin: 0; }
            </style>
          </head>
          <body>
            <main>
              <h1>We'll be right back</h1>
              <p>We're upgrading. Back at 14:00 UTC.</p>
            </main>
          </body>
          </html>
```

A browser gets the page. `curl -H 'Accept: application/json'` gets `message` as JSON.

Maintenance mode is part of the route configuration, so it can be switched on and off with a configuration reload, without restarting the gateway.
