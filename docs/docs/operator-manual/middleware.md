---
title: Middleware
sidebar_label: Middleware
sidebar_position: 3
---

# Middleware

A **Middleware** is a reusable request/response processor — authentication, rate limiting, header rewriting, redirects, and more. A `Middleware` resource is referenced by name from one or more [Routes](./route.md) (`spec.middlewares`) or attached to monitoring endpoints from a [Gateway](./gateway.md#observability).

- **API group:** `gateway.jkaninda.dev`
- **Version:** `v1alpha1`
- **Kind:** `Middleware`

The `spec.rule` field is a free-form object whose shape depends on `spec.type`. The sections below show common examples.

## Supported types

`spec.type` is validated against the list below. The `rule` for each type is the same as in the gateway's own configuration, documented on the linked pages.

| Type | Purpose |
| --- | --- |
| [`basic`](../middlewares/basic.md) | HTTP basic authentication. |
| [`jwt`](../middlewares/jwt.md) | JWT validation (shared secret, public key, or JWKS). |
| [`ldap`](../middlewares/ldap.md) | LDAP authentication. |
| [`forwardAuth`](../middlewares/forward-auth.md) | Delegate authn/authz to an external HTTP service. |
| [`rateLimit`](../middlewares/rate-limit.md) | Request rate limiting. |
| [`access`](../middlewares/access.md) | Block access to specific paths. |
| [`accessPolicy`](../middlewares/access-policy.md) | Allow / deny requests by client IP or CIDR. |
| [`addPrefix`](../middlewares/add-prefix.md) | Prepend a prefix to the request path. |
| [`redirectRegex`](../middlewares/redirect-regex.md) | Regex-based redirect. |
| [`rewriteRegex`](../middlewares/rewrite-regex.md) | Regex-based path rewrite. |
| [`redirectScheme`](../middlewares/redirect-scheme.md) | Force HTTP → HTTPS redirects. |
| [`httpCache`](../middlewares/http-caching.md) | HTTP response cache. |
| [`bodyLimit`](../middlewares/body-limit.md) | Limit request body size. |
| [`responseHeaders`](../middlewares/response-headers.md) | Set response headers and CORS. |
| [`errorInterceptor`](../middlewares/error-interceptor.md) | Map upstream error codes to custom responses. |
| [`userAgentBlock`](../middlewares/user-agent-block.md) | Block requests by User-Agent pattern. |

:::warning
The `Middleware` CRD does not yet accept `oidc`, `geoBlock`, `requestHeaders`, `accessLog`, `redirect`, or `stripQuery`, nor the `basicAuth` / `jwtAuth` / `ldapAuth` spellings. It still lists `oauth`, which [was removed in Goma Gateway v1.0](../middlewares/oauth.md): a gateway given an `oauth` middleware refuses to start.
:::

## Basic auth

Store hashed passwords (bcrypt recommended; see [Basic auth](../middlewares/basic.md) for the other accepted formats). Generate a bcrypt entry with:

```sh
htpasswd -nbB admin 's3cret'
```

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Middleware
metadata:
  name: admin-basic-auth
spec:
  type: basic
  paths:
    - /admin
  rule:
    realm: admin
    users:
      - "admin:$2a$12$EXAMPLEHASHREPLACEME.................."
```

## Rate limiting

Rate limiter, keyed by client IP by default. When the parent Gateway is configured with a Redis backend, counters are shared across replicas.

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Middleware
metadata:
  name: api-rate-limit
spec:
  type: rateLimit
  rule:
    requestsPerUnit: 100
    unit: minute       # second | minute | hour
    burst: 20
```

## JWT authentication

Validate tokens against a remote JWKS endpoint (Auth0, Keycloak, Okta, etc.).

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Middleware
metadata:
  name: api-jwt
spec:
  type: jwt
  rule:
    jwksUrl: https://auth.example.com/.well-known/jwks.json
    issuer: https://auth.example.com/
    audience: api.example.com
    algorithms:
      - RS256
    forward:
      headers:
        X-User-Id: sub
        X-User-Email: email
```

Optional `claimsExpression` lets you assert claim values (see [Claims validation](../middlewares/jwt.md#claims-validation)):

```yaml
spec:
  type: jwt
  rule:
    jwksUrl: https://auth.example.com/.well-known/jwks.json
    issuer: https://auth.example.com/
    audience: api.example.com
    algorithms:
      - RS256
    claimsExpression: >
      Equals('email_verified', true) && !Equals('account_disabled', true)
    forward:
      headers:
        X-User-ID: sub
        X-User-Email: email
```

## Forward auth

Delegate authentication and authorization to an external HTTP endpoint. The gateway sends a subrequest to `authUrl` — a 2xx response allows the request through; otherwise the request is denied. When the auth service answers `401` and `authSignIn` is set, the client is redirected there instead.

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Middleware
metadata:
  name: forward-auth
spec:
  type: forwardAuth
  rule:
    authUrl: http://auth.default.svc.cluster.local:8080/verify
    authSignIn: https://app.example.com/login
    forwardHostHeaders: true
    authResponseHeaders:
      - X-User-Id
      - X-User-Roles
```

## Attaching to routes

Reference middlewares by name from a `Route`:

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Route
metadata:
  name: api
spec:
  gateways:
    - gateway
  path: /
  hosts:
    - api.example.com
  target: http://api.default.svc.cluster.local:8080
  middlewares:
    - api-jwt
    - api-rate-limit
```

The order matters — middlewares run in the order they appear in `spec.middlewares`.

## Path scoping

`spec.paths` constrains the middleware to a subset of paths within the route it's attached to. Entries are case-insensitive regular expressions anchored to the start of the path (but not the end), tried both as written and relative to the route's `path`; see [Path patterns](../middlewares/overview.md#path-patterns). For `basic`, `jwt`, `forwardAuth` and `access`, an empty `paths` list covers the whole route.

```yaml
spec:
  type: basic
  paths:
    - ^/admin(/.*)?$   # /admin and everything under it
  rule:
    realm: admin
    users:
      - "admin:$2a$12$EXAMPLEHASHREPLACEME.................."
```

## Spec reference

| Field | Type | Description |
| --- | --- | --- |
| `type` | enum | **Required.** Middleware type (see [Supported types](#supported-types)). |
| `paths` | []string | Paths within the attached route to apply this middleware to. |
| `rule` | object | Type-specific configuration. Schema depends on `type`. |

`rule` is preserved as-is by the API server (`x-kubernetes-preserve-unknown-fields`), so any field accepted by the corresponding gateway middleware can be set here.

## Status

```sh
kubectl get middlewares
```

```
NAME              TYPE        READY   AGE
admin-basic-auth  basic       true    3m
api-jwt           jwt         true    3m
api-rate-limit    rateLimit   true    3m
```

`status.referencedBy` lists Routes that consume the middleware. `Ready: true` means the rule is well-formed and synced.
