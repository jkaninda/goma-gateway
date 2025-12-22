---
title: Response Headers Middleware
layout: default
parent: Middlewares
nav_order: 16
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
          - OPTIONS
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
| `rule.cors.origins`          | array   | No       | Allowed origins (default: `*` if not specified)                |
| `rule.cors.allowMethods`     | array   | No       | Allowed HTTP methods (default: `GET`, `POST`, `OPTIONS`)       |
| `rule.cors.allowCredentials` | boolean | No       | Allows credentials in cross-origin requests (default: `false`) |

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

### Behavior

* A non-empty value **adds or overrides** the header
* An empty string (`""`) **removes** the header from the response

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