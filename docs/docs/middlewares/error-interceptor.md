---
title: Error Interceptor
sidebar_label: Error Interceptor
sidebar_position: 17
---

# Error Interceptor Middleware

The **Error Interceptor Middleware** (`errorInterceptor`) allows you to intercept, transform, and standardize error responses returned by backend services. It is particularly useful for enforcing consistent error formats, improving user experience, and handling service failures gracefully.

---

## Overview

When enabled, the `errorInterceptor` middleware inspects the route's responses and replaces those whose status code is listed in `errors`. This covers backend responses and errors produced by the route's other middlewares (for example a `401` from `jwtAuth`). For matched errors, you can:

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
middlewares:
  - name: error-interceptor
    type: errorInterceptor
    rule:
      enabled: true
      errors:
        - statusCode: 400
        - statusCode: 500
```

An entry without `body` or `file` replaces the backend's body with the status
text, e.g. `500 Internal Server Error`.

### Configuration Options

| Parameter            | Type    | Default | Description                                                                                 |
|----------------------|---------|---------|---------------------------------------------------------------------------------------------|
| `enabled`            | boolean | `false` | Must be `true` for anything to be intercepted.                                              |
| `contentType`        | string  | request's `Accept` header | Response format: `application/json`, `application/xml`, or anything else for plain text. |
| `errors`             | list    | required | Status codes to intercept.                                                                  |
| `errors[].statusCode`| integer | -       | Status code to intercept. The original status code is kept in the response.                |
| `errors[].body`      | string  | -       | Replacement body.                                                                           |
| `errors[].file`      | string  | -       | Path to a file served as `text/html` instead of `body`.                                     |

With `contentType: application/json`, a `body` that is valid JSON is returned
as-is; any other body is wrapped as `{"success": false, "statusCode": <code>, "error": "<body>"}`.

`code` and `status` inside `errors` were removed in v1.0; use `statusCode`. The
route-level `errorInterceptor` block was also removed: configure this middleware
and attach it to the route instead.


---

## Advanced Configuration (Custom JSON Responses)

You can define fully customized response bodies for each intercepted status code. This is ideal for APIs that require a consistent error schema.

```yaml
middlewares:
  - name: error-interceptor
    type: errorInterceptor
    rule:
      enabled: true
      contentType: application/json
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
middlewares:
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

Some responses are never intercepted: WebSocket and Server-Sent Events
requests, file downloads (`Content-Disposition: attachment`), binary
`application/*` types other than JSON and XML, audio and video, and bodies
declared larger than 10 MB.

