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
        maxAge: 86400
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
* **`origins`** (`[]string`): Allowed origins, each with a scheme and no path (`https://app.example.com`). Required when `enabled` is `true`. A single `*` allows any origin; it cannot be combined with other origins.
* **`allowedHeaders`** (`[]string`): Headers allowed in requests. When empty, the headers the browser asks for in a preflight are allowed.
* **`exposeHeaders`** (`[]string`): Headers the browser may read from the response.
* **`maxAge`** (`int`): How long, in seconds, a preflight result may be cached. Must be between `0` and `86400`.
* **`allowMethods`** (`[]string`): Allowed HTTP methods. When empty, the method the browser asks for in a preflight is allowed. Do not list `OPTIONS`; preflights are handled automatically.
* **`allowCredentials`** (`boolean`): Whether cookies and authorization headers are allowed. Cannot be combined with a `*` origin.

:::warning
A policy that fails these checks is not applied. The gateway logs
`Response headers middleware not applied` and serves the route without the
middleware, including its `setHeaders`. Check the logs after changing a policy.
:::

Response headers that are not part of the CORS contract belong in the same
middleware's `setHeaders`, which is where the removed `cors.headers` map moved.

---

## Applying one policy to several routes

There is no dedicated global CORS block. To apply the same policy to several
routes, list the middleware on each of them:

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

To apply it to every route instead, name it in
[`gateway.defaults.middlewares`](gateway.md#default-configuration), which
prepends the listed middlewares to each route.

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

The gateway answers a preflight (`OPTIONS`) request itself with `204 No Content`
when the request's `Origin` matches one of the route's CORS policies, and does
not forward it to the backend. Backends do not need their own `OPTIONS` handling
for routes that have a CORS policy.

:::note
If the route restricts `methods`, include `OPTIONS` in the list. The method
check runs before the preflight is handled, so a route that does not allow
`OPTIONS` answers preflights with `405 Method Not Allowed`.
:::
