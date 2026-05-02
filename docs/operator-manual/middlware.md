---
title: Middleware
layout: default
parent: Operator Manual
nav_order: 3
---

# Middleware

A **Middleware** is a reusable request/response processor — authentication, rate limiting, header rewriting, redirects, and more. A `Middleware` resource is referenced by name from one or more [Routes](./route.md) (`spec.middlewares`) or attached to monitoring endpoints from a [Gateway](./gateway.md#observability).

- **API group:** `gateway.jkaninda.dev`
- **Version:** `v1alpha1`
- **Kind:** `Middleware`

The `spec.rule` field is a free-form object whose shape depends on `spec.type`. The sections below document each supported type.

## Supported types

| Type | Purpose |
| --- | --- |
| `basic` | HTTP basic authentication. |
| `jwt` / `jwtAuth` | JWT validation against a JWKS endpoint. |
| `oauth` | OAuth 2.0 authentication flow. |
| `forwardAuth` | Delegate authn/authz to an external HTTP service. |
| `ldap` | LDAP authentication. |
| `rateLimit` | Per-IP / per-route rate limiting. |
| `access` | Allow / deny rules by IP, header, etc. |
| `accessPolicy` | Fine-grained access policies. |
| `addPrefix` | Prepend a prefix to the request path. |
| `redirectRegex` | Regex-based redirect. |
| `rewriteRegex` | Regex-based path rewrite. |
| `redirectScheme` | Force HTTP → HTTPS redirects. |
| `httpCache` | HTTP response cache. |
| `bodyLimit` | Limit request body size. |
| `responseHeaders` | Add / remove response headers. |
| `errorInterceptor` | Map upstream error codes to custom responses. |
| `userAgentBlock` | Block requests by User-Agent pattern. |

## Basic auth

Passwords must be bcrypt-hashed. Generate with:

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

Per-IP rate limiter. When the parent Gateway is configured with a Redis backend, counters are shared across replicas.

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
  type: jwtAuth
  rule:
    jwksUrl: https://auth.example.com/.well-known/jwks.json
    issuer: https://auth.example.com/
    audience: api.example.com
    algorithms:
      - RS256
    forwardHeaders:
      X-User-Id: sub
      X-User-Email: email
```

Optional `claimsExpression` lets you assert claim values:

```yaml
spec:
  type: jwtAuth
  rule:
    jwksUrl: https://auth.example.com/.well-known/jwks.json
    issuer: https://auth.example.com/
    audience: api.example.com
    algo: RS256
    claimsExpression: >
      Equals('email_verified', true) && !Equals('account_disabled', true)
    forwardHeaders:
      X-User-ID: sub
      X-User-Email: email
```

## Forward auth

Delegate authentication and authorization to an external HTTP endpoint. The gateway sends a subrequest to `authUrl` — a 2xx response allows the request through, anything else is returned to the client.

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
    trustForwardHeader: true
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

`spec.paths` constrains the middleware to a subset of paths within the route it's attached to. Use it for fine-grained protection:

```yaml
spec:
  type: basic
  paths:
    - /admin       # exact
    - /admin/*     # subpaths
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
api-jwt           jwtAuth     true    3m
api-rate-limit    rateLimit   true    3m
```

`status.referencedBy` lists Routes that consume the middleware. `Ready: true` means the rule is well-formed and synced.
