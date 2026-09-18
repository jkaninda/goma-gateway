---
title: Cross-Origin Resource Sharing (CORS)
sidebar_label: Cross-Origin Resource Sharing (CORS)
sidebar_position: 4
---

# Cross-Origin Resource Sharing (CORS)

CORS defines which origins a browser will let read your API's responses. In
Goma Gateway it is configured with the
[`responseHeaders` middleware](../middlewares/response-headers.md), applied to
the routes that need it.

:::warning[Removed in v1.0]

The `cors` block on the gateway and on individual routes was removed in v1.0,
along with the `headers` map inside it. A configuration that still uses one will
not start. See the [v1.0 upgrade note](../upgrade/v1.0.md) for the full list, or
run `goma config check -c <file>` to have the gateway point at them.

:::

---

## Configuring CORS

Define the policy once as a middleware and apply it to each route:

```yaml
version: 2
middlewares:
  - name: api-cors
    type: responseHeaders
    rule:
      cors:
        enabled: true
        origins:
          - http://localhost:3000
          - https://dev.example.com
        allowedHeaders:
          - Origin
          - Authorization
          - X-Client-Id
          - Content-Type
          - Accept
        exposeHeaders: []
        maxAge: 1728000
        allowMethods: ["GET", "POST"]
        allowCredentials: true
      setHeaders:
        X-Session-Id: xxx-xxx-xx

gateway:
  routes:
    - name: example
      path: /
      target: https://api.example.com
      middlewares: [api-cors]
```

### Configuration fields

* **`enabled`** (`boolean`): Whether this policy applies. Defaults to `false`.
* **`origins`** (`[]string`): Allowed origin URLs.
* **`allowedHeaders`** (`[]string`): Headers allowed in requests.
* **`exposeHeaders`** (`[]string`): Headers the browser may read from the response.
* **`maxAge`** (`int`): How long, in seconds, a preflight result may be cached. Capped at 86400.
* **`allowMethods`** (`[]string`): Allowed HTTP methods. Empty allows all.
* **`allowCredentials`** (`boolean`): Whether cookies and authorization headers are allowed. Cannot be combined with a `*` origin.

Response headers that are not part of the CORS contract belong in the same
middleware's `setHeaders`, which is where the removed `cors.headers` map moved.

---

## Applying one policy to every route

There is no global CORS setting. To apply the same policy everywhere, list the
middleware on each route:

```yaml
gateway:
  routes:
    - name: api
      path: /api
      target: http://api:8080
      middlewares: [api-cors]
    - name: web
      path: /
      target: http://web:3000
      middlewares: [api-cors]
```

This is more typing than the removed global block, but it makes each route's
policy visible where the route is defined, and lets a route opt out or use a
stricter policy without inheriting one it did not ask for.

---

## CORS on gateway error responses

Some responses never reach your backend: a 405 for a method the route does not
allow, or a 503 when every backend is failing its health check. The gateway
generates these itself, so they carry none of the CORS headers your backend
would have set.

The gateway puts the origins from the route's `responseHeaders` CORS policies on
these responses, so the browser lets the caller read the status. A route with no
CORS policy returns them without an `Access-Control-Allow-Origin`, and the
browser reports an opaque network error instead of the real status. If a browser
needs to distinguish a 503 from a 404 on a route, give that route a CORS policy.

---

## Preflight requests

The gateway answers a preflight (`OPTIONS`) request itself when the request's
`Origin` matches one of the route's CORS policies, and does not forward it to
the backend. Backends do not need their own `OPTIONS` handling for routes that
have a CORS policy.
