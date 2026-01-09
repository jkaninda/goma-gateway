---
title: Error Interceptor
layout: default
parent: Middlewares
nav_order: 17
---

# Error Interceptor Middleware

The **Error Interceptor Middleware** (`errorInterceptor`) allows you to intercept, transform, and standardize error responses returned by backend services. It is particularly useful for enforcing consistent error formats, improving user experience, and handling service failures gracefully.

---

## Overview

When enabled, the `errorInterceptor` middleware inspects backend responses and intercepts HTTP error status codes (typically **4xx** and **5xx**). For matched errors, you can:

* Override response bodies
* Serve custom error templates (HTML or other formats)
* Standardize API error payloads
* Improve frontend and API consumer experience
* Mask internal backend errors
* Handle gateway-level fallback scenarios

### Typical Use Cases

* Unifying error response formats across multiple services
* Customizing error messages for APIs or UI clients
* Returning user-friendly error pages
* Preventing backend error leakage
* Improving observability and debugging workflows

---

## Basic Configuration

The following example enables the middleware and intercepts specific HTTP status codes:

```yaml
- name: error-interceptor
  type: errorInterceptor
  rule:
    enabled: true
    errors:
      - statusCode: 400
      - statusCode: 500
```


---

## Advanced Configuration (Custom JSON Responses)

You can define fully customized response bodies for each intercepted status code. This is ideal for APIs that require a consistent error schema.

```yaml
- name: error-interceptor
  type: errorInterceptor
  rule:
    enabled: true
    errors:
      - statusCode: 405

      - statusCode: 400
        body: >
          {"success": false, "code": 400, "message": "Bad Request", "data": null}

      - statusCode: 401
        body: >
          {"success": false, "code": 401, "message": "Unauthorized", "data": null}

      - statusCode: 403
        body: >
          {"success": false, "code": 403, "message": "Forbidden", "data": null}

      - statusCode: 404
        body: >
          {"success": false, "code": 404, "message": "Not Found", "data": null}

      - statusCode: 500
        body: >
          {"success": false, "code": 500, "message": "Internal Server Error", "data": null}
```

---

## Custom Error Responses Using Templates

For UI-oriented routes, you can serve static error pages (HTML, JSON, etc.) from files.

```yaml
- name: error-interceptor-ui
  type: errorInterceptor
  rule:
    enabled: true
    errors:
      - statusCode: 403
        file: /etc/goma/errors/403.html

      - statusCode: 502
        file: /etc/goma/errors/502.html
        
      - statusCode: 503
        file: /etc/goma/errors/503.html
```

### Use Cases

* Serving branded error pages
* Handling maintenance or upstream outages
* Improving UX for browser-based clients

> Ensure the goma gateway has read access to the specified files.

---

## Applying the Middleware to Routes

Once defined, reference the middleware in your route configuration:

```yaml
routes:
  - name: api-route
    path: /api
    backends:
      - endpoint: http://backend-service
    middlewares:
      - error-interceptor
```

The middleware will be applied in the order defined, intercepting backend responses before they are returned to the client.

