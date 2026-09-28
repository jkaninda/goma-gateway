---
title: Response Headers
sidebar_label: Response Headers
sidebar_position: 16
---

# Response Headers Middleware

The **Response Headers Middleware** (`responseHeaders`) allows you to **add, modify, or remove HTTP response headers** before they are sent to clients. It is commonly used to improve security, manage caching behavior, configure CORS, and inject custom metadata.

---

## Overview

The `responseHeaders` middleware intercepts outgoing HTTP responses and applies a set of header rules. It can be used to:

* Add security headers (e.g. `Content-Security-Policy`, `X-Frame-Options`)
* Control caching behavior (`Cache-Control`, `Expires`)
* Configure Cross-Origin Resource Sharing (CORS)
* Inject custom metadata (`X-Request-ID`, `X-Powered-By`)
* Remove sensitive or unwanted headers (`Server`, `X-Powered-By`)
* Improve SEO and compliance with organizational policies

---

## Basic Configuration

### Middleware Structure

```yaml
middlewares:
  - name: response-headers
    type: responseHeaders
    rule:
      cors:
        enabled: false
```

---

## CORS Configuration

The `cors` section enables Cross-Origin Resource Sharing headers on responses.

### Example

```yaml
middlewares:
  - name: enable-cors
    type: responseHeaders
    rule:
      cors:
        enabled: true
        origins:
          - https://example.com
          - https://anotherdomain.com
        allowMethods:
          - GET
          - POST
        allowCredentials: true
```

This configuration:

* Allows requests from the specified origins
* Permits the listed HTTP methods
* Enables credentialed requests (cookies, authorization headers)

---

### CORS Parameters

| Parameter                    | Type    | Required | Description                                                    |
|------------------------------|---------|----------|----------------------------------------------------------------|
| `rule.cors.enabled`          | boolean | No       | Enables or disables CORS support (default: `false`)            |
| `rule.cors.origins`          | array   | Yes, when enabled | Allowed origins, with scheme (`https://example.com`), or a single `*` |
| `rule.cors.allowMethods`     | array   | No       | Allowed HTTP methods. Do not list `OPTIONS`, which is handled automatically. When empty, the preflight's requested method is echoed |
| `rule.cors.allowedHeaders`   | array   | No       | Allowed request headers. When empty, the preflight's requested headers are echoed |
| `rule.cors.exposeHeaders`    | array   | No       | Response headers exposed to the browser                        |
| `rule.cors.maxAge`           | integer | No       | Preflight cache duration in seconds, at most `86400`. Not sent when unset |
| `rule.cors.allowCredentials` | boolean | No       | Allows credentials in cross-origin requests (default: `false`) |

CORS headers are only added when the request's `Origin` is allowed, and they
override any CORS headers sent by the backend. An invalid CORS block (for
example `OPTIONS` in `allowMethods`, an origin without a scheme, or `*` combined
with other origins) is logged and the middleware is not applied.

---

## Managing Custom Response Headers

You can explicitly set, override, or remove response headers using the `setHeaders` section.

```yaml
middlewares:
  - name: custom-headers
    type: responseHeaders
    rule:
      setHeaders:
        X-Powered-By: Goma Gateway
        Server: ""              # Removes the Server header
```

### Setting Cookie

```yaml
middlewares:
  - name: custom-headers
    type: responseHeaders
    rule:
      setHeaders:
        X-Powered-By: Goma Gateway
        Server: ""              # Removes the Server header
      setCookies:
        - name: SecureCookie
          value: "${COOKIE_NAME}" # Example of using environment variable
          attributes:
            secure: true
            httpOnly: true
            sameSite: Strict
        - name: AnotherCookie
          value: "SomeValue"
          attributes:
            path: /
            maxAge: 3600       # 0 = session cookie, -1 = delete
            secure: true
            httpOnly: true
            sameSite: Lax
```

Cookie `attributes`: `path`, `domain`, `maxAge`, `secure`, `httpOnly`,
`sameSite` (`Strict`, `Lax` or `None`). An empty `value` or `maxAge: -1` deletes
the cookie.

### Behavior

* A non-empty value **adds or overrides** the header. It is only applied to
  `200 OK` responses; other statuses keep the backend's headers
  (`Cache-Control` set through `setHeaders` is the exception and applies to every status)
* An empty string (`""`) **removes** the header from the response, whatever the status
* `Content-Length`, `Transfer-Encoding`, `Trailer`, `Connection` and `Upgrade` cannot be set
* With `paths`, a policy applies only to matching request paths; the patterns are
  matched against the full request path. When several policies match, shorter
  (more general) paths are applied first, so the most specific one wins

---

## Cache-Control Configuration

To control response caching, you can define a `cacheControl` directive. This automatically sets the `Cache-Control` header.

```yaml
middlewares:
  - name: cache-control
    type: responseHeaders
    rule:
      cacheControl: "public, max-age=300"
```

> If `cacheControl` is defined, it overrides any existing `Cache-Control` header from the backend.

### Restricting caching to specific status codes

By default `cacheControl` is applied to **every** response. Use `cacheStatuses`
to apply it only when the backend returned one of the listed status codes —
useful for caching successful responses while leaving errors uncacheable.

```yaml
middlewares:
  - name: cache-successful-only
    type: responseHeaders
    rule:
      cacheControl: "public, max-age=300"
      cacheStatuses: [200, 203, 301]
```

| Parameter       | Type    | Required | Description                                                                                  |
|-----------------|---------|----------|----------------------------------------------------------------------------------------------|
| `cacheControl`  | string  | No       | Value for the `Cache-Control` response header.                                               |
| `cacheStatuses` | `[]int` | No       | Status codes that `cacheControl` applies to. **Empty or omitted applies it to all statuses.** |

A response whose status is not in `cacheStatuses` is passed through with the
backend's own `Cache-Control` header untouched.

---

## Advanced Configuration (Combined Example)

```yaml
middlewares:
  - name: response-headers-advanced
    type: responseHeaders
    rule:
      cors:
        enabled: true
        origins:
          - https://example.com
        allowMethods:
          - GET
          - POST
        allowCredentials: true

      setHeaders:
        X-Frame-Options: DENY
        X-Content-Type-Options: nosniff
        Referrer-Policy: strict-origin-when-cross-origin
        Server: ""

      cacheControl: "no-store, no-cache, must-revalidate"
```


## Applying the Middleware to Routes

```yaml
routes:
  - name: api-route
    path: /api
    backends:
      - endpoint: http://backend-service
    middlewares:
      - response-headers-advanced
```

### Route-Specific Metadata

Header values can reference `{route.name}`, `{route.path}`, `{route.target}` and
`{gateway.version}`. They are resolved when the configuration is loaded.

```yaml
middlewares:
  - name: route-metadata
    type: responseHeaders
    rule:
      setHeaders:
        X-API-Route: "{route.path}"
        X-Backend-Service: "{route.target}"
        X-Goma-Route: "{route.name}"
        X-Goma-Route-PATH: "{route.path}"
        X-Debug-Info: "Gateway {gateway.version} - ${INSTANCE_ID} | Route: {route.name}"
```