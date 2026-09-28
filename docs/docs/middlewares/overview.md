---
title: Overview
sidebar_label: Overview
sidebar_position: 1
---
# Middlewares

Middlewares run on a route's requests before they reach the backend, and some
also act on the response. They are how Goma Gateway authenticates callers,
enforces access rules, shapes traffic and rewrites requests at the edge.

A middleware is defined once in the top-level `middlewares` list and attached to
routes by name. Middlewares listed in `gateway.defaults.middlewares` apply to
every route (see [Default Configuration](../usermanual/gateway.md#default-configuration)).

```yaml
middlewares:
  - name: api-auth
    type: jwtAuth
    paths:
      - /.*
    rule:
      secret: ${JWT_SECRET}
      algorithms: ["HS256"]

gateway:
  routes:
    - name: api
      path: /api
      target: http://api:8080
      middlewares:
        - api-auth
```

Request middlewares run in the order they are listed on the route.

## Middleware Types

### Authentication

| Type                  | Description                                                              | Page                             |
|-----------------------|--------------------------------------------------------------------------|----------------------------------|
| `basicAuth`, `basic`  | HTTP Basic authentication against a list of users                        | [Basic auth](basic.md)           |
| `jwtAuth`, `jwt`      | Validates JSON Web Tokens and forwards verified claims                   | [JWT](jwt.md)                    |
| `oidc`                | OpenID Connect browser login with sessions kept at the gateway           | [OpenID Connect](oidc.md)        |
| `ldapAuth`, `ldap`    | HTTP Basic authentication against an LDAP / Active Directory server      | [LDAP auth](ldap.md)             |
| `forwardAuth`         | Delegates the decision to an external authentication service             | [ForwardAuth](forward-auth.md)   |

`type: oauth` and `type: oauth2` were removed in v1.0; use `oidc` (see [OAuth](oauth.md)).

### Access Control

| Type              | Description                                                   | Page                                    |
|-------------------|---------------------------------------------------------------|-----------------------------------------|
| `access`          | Blocks requests to specific paths                             | [Access](access.md)                     |
| `accessPolicy`    | Allows or denies client IPs, ranges and CIDR blocks           | [Access Policy](access-policy.md)       |
| `geoBlock`        | Allows or denies countries resolved from a GeoIP database     | [Geo Block](geo-block.md)               |
| `userAgentBlock`  | Blocks requests by `User-Agent`                               | [User Agent Block](user-agent-block.md) |
| `rateLimit`       | Per-client rate limiting, in memory or in Redis, with bans    | [Rate Limiting](rate-limit.md)          |
| `bodyLimit`       | Caps the request body size                                    | [Body Limit](body-limit.md)             |

### Request and Response

| Type               | Description                                               | Page                                    |
|--------------------|-----------------------------------------------------------|-----------------------------------------|
| `addPrefix`        | Adds a prefix to the request path                         | [AddPrefix](add-prefix.md)              |
| `rewriteRegex`     | Rewrites the request path with a regular expression       | [RewriteRegex](rewrite-regex.md)        |
| `stripQuery`       | Removes named query parameters                            | [Strip Query](strip-query.md)           |
| `requestHeaders`   | Sets or removes request headers                           | [Request Headers](request-headers.md)   |
| `responseHeaders`  | Sets response headers and cookies, CORS, `Cache-Control`  | [Response Headers](response-headers.md) |
| `httpCache`        | Caches responses in memory or in Redis                    | [HTTP Caching](http-caching.md)         |

### Redirects

| Type              | Description                                          | Page                                  |
|-------------------|------------------------------------------------------|---------------------------------------|
| `redirect`        | Redirects every request to a fixed URL               | [Redirect](redirect.md)               |
| `redirectRegex`   | Redirects requests matching a regular expression     | [RedirectRegex](redirect-regex.md)    |
| `redirectScheme`  | Redirects to another scheme, e.g. HTTP to HTTPS      | [RedirectScheme](redirect-scheme.md)  |

### Observability and Errors

| Type                | Description                                            | Page                                        |
|---------------------|--------------------------------------------------------|---------------------------------------------|
| `accessLog`         | Adds request headers, query parameters and cookies to the access log | [Access Log](access-log.md)  |
| `errorInterceptor`  | Replaces error responses with custom bodies or pages   | [Error Interceptor](error-interceptor.md)   |

A route can also reference a middleware provided by a
[custom module](../usermanual/module.md) by its name.

## Configuration Options

- **`name`** (`string`): Unique name of the middleware, used to attach it to routes.
- **`type`** (`string`): Type of the middleware, from the tables above.
- **`paths`** (`array of string`): Paths the middleware applies to. See [Path patterns](#path-patterns).
- **`rule`** (`dictionary`): Middleware rule; its keys depend on the type.

An unknown key inside `rule` is ignored at startup with a warning
(`Unknown configuration key is ignored`); `goma config check` reports it as an
error, along with rules that fail the middleware's own validation.

If the rule of a `basicAuth`, `ldapAuth`, `jwtAuth`, `forwardAuth`, `oidc`,
`access`, `accessPolicy` or `geoBlock` middleware is invalid, the gateway logs an
error and every route using it rejects all requests with `503` until the rule is
fixed. A route that references an undefined middleware, or a middleware whose
type is neither built in nor a loaded plugin, also answers `503`. Other
middleware types with an invalid rule are logged and skipped.

### Which middlewares use `paths`

| Middlewares                                                             | `paths` omitted              | `paths` set                         |
|-------------------------------------------------------------------------|------------------------------|-------------------------------------|
| `basicAuth`, `jwtAuth`, `oidc`, `ldapAuth`, `forwardAuth`, `access`     | Applies to the whole route   | Applies to matching paths only      |
| `rateLimit`, `requestHeaders`, `responseHeaders`                        | Applies to the whole route   | Applies to matching paths only      |
| `httpCache`                                                             | Caches **nothing**           | Caches matching paths only          |
| All other types                                                         | `paths` is ignored; the middleware applies to the whole route (`stripQuery` has its own `pathPattern`) | |

## Path patterns

A path is matched as a **regular expression** first, and as a wildcard only if it
is not a valid regular expression:

```yaml
paths:
  - /.*                # everything on the route
  - /admin/.*          # everything under /admin
  - ^/api/v[0-9]+/.*$  # versioned API paths
```

**Patterns are anchored at the start, not at the end.** `/admin` matches
`/admin`, `/admin/settings` and also `/administrator`, but not
`/public/admin/notes`. Add `$` or a trailing group when you mean a specific path:

```yaml
  - ^/admin$        # exactly /admin
  - ^/admin(/.*)?$  # /admin and everything under it
```

**Patterns are also tried relative to the route.** On a route at `/api`, the
pattern `/admin` covers both `/admin...` and `/api/admin...`. A pattern that
starts with `^` is only matched against the full request path.

**Matching is case-insensitive.** `/admin/.*` also matches `/Admin/users`, which
is deliberate: many backends treat the two as the same resource, and a rule that
only covered the lowercase form could be walked around by changing the case.

The wildcard form (`/admin/*`) is still accepted for existing configurations,
but most such patterns are valid regular expressions and are matched as one:
`/admin/*` means `/admin` followed by any number of slashes, so it matches
`/admin/users` and also `/administrator`. A pattern such as `/tenant/*/api/*`
does not match `/tenant/a/api/b`. Write the regular expression form
(`/admin/.*`, `/tenant/[^/]+/api/.*`) instead. When a pattern is not a valid
regular expression, the gateway logs the regex form to replace it with.
