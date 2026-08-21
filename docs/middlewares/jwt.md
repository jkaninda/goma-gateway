---
title: JWT
layout: default
parent: Middlewares
nav_order: 13
---

# JWT Middleware

The **JWT Middleware** validates JSON Web Tokens (JWT) in incoming requests to ensure only authenticated requests reach your upstream services. It provides flexible authentication methods and advanced claim validation capabilities.

## Quick Start

```yaml
middlewares:
  - name: jwt-auth
    type: jwtAuth
    paths: ["/.*"]
    rule:
      secret: "your-secret-key-here"
      algorithms: ["HS256"]
```

## Authentication Methods

The middleware supports four authentication methods. **You must configure exactly one**:

###  Shared Secret (HMAC)
Use a shared secret key for HMAC algorithms like HS256, HS384, or HS512.

```yaml
rule:
  secret: "MgsEUFgn9xiMym9Lo9rcRUa3wJbQBo..."
  algorithms: ["HS256"]
```

###  Public Key (RSA/ECDSA)
Use a PEM-formatted public key for RSA or ECDSA algorithms.

```yaml
rule:
  publicKey: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
  algorithms: ["RS256"]
```

You can also provide:
- **File path**: `/path/to/public-key.pem`
- **Base64 encoded key**: `LS0tLS1CRUdJTi...`

### JWKS URL
Dynamically fetch public keys from a JSON Web Key Set endpoint.

```yaml
rule:
  jwksUrl: "https://your-auth-provider.com/.well-known/jwks.json"
  algorithms: ["RS256"]
```

### JWKS File
Use a local JWKS file for key validation.

```yaml
rule:
  jwksFile: "/path/to/jwks.json"
  # Or embed the content directly:
  # jwksFile: '{"keys":[{"kty":"RSA",...}]}'
```

## Configuration Reference

### Core Settings

| Option       | Type     | Required | Description                                                    |
|--------------|----------|----------|---------------------------------------------------------------|
| `secret`     | string   | *        | Shared secret for HMAC algorithms                             |
| `publicKey`  | string   | *        | PEM public key (content, file path, or base64)                |
| `jwksUrl`    | string   | *        | URL to fetch JWKS dynamically                                 |
| `jwksFile`   | string   | *        | JWKS file path or content                                     |
| `algorithms` | []string | No       | Accepted JWT signing algorithms, e.g. `["RS256", "ES256"]`    |
| `algo`       | string   | No       | **Deprecated** — use `algorithms`. Single accepted algorithm. |

**\* One of these four options is required**

> **Algorithm selection.** When `algorithms` (and the deprecated `algo`) are
> omitted, the gateway accepts a safe set scoped to the configured key type: the
> HMAC family (`HS256/384/512`) for a shared `secret`, and asymmetric algorithms
> (`RS*`, `ES*`, `PS*`) for `publicKey` / `jwksUrl` / `jwksFile`. An HMAC token is
> never accepted against an asymmetric key, preventing algorithm-confusion
> attacks. Set `algorithms` to pin an explicit list.

### Token Validation

| Option             | Type   | Description                                    | Example                                     |
|--------------------|--------|------------------------------------------------|---------------------------------------------|
| `issuer`           | string | Expected `iss` claim value                     | `"https://auth.example.com"`                |
| `audience`         | string | Expected `aud` claim value                     | `"api.example.com"`                         |
| `claimsExpression` | string | Boolean expression for custom claim validation | See [Claims Validation](#claims-validation) |

### Claim Forwarding

| Option                 | Type    | Description                                                                     |
|------------------------|---------|---------------------------------------------------------------------------------|
| `forward`              | map     | Project claims onto the upstream request as headers, query parameters and cookies |
| `forwardHeaders`       | map     | Deprecated: use `forward.headers`                                                |
| `forwardAuthorization` | boolean | Whether to forward the original `Authorization` header (default: `true`)         |

## Claims Validation

Use `claimsExpression` to implement complex validation logic with boolean expressions:

### Available Functions

| Function   | Purpose                      | Syntax                          | Example                              |
|------------|------------------------------|---------------------------------|--------------------------------------|
| `Equals`   | Exact match comparison       | `Equals(claim, value)`          | `Equals('email_verified', true)`     |
| `Prefix`   | String starts with           | `Prefix(claim, prefix)`         | `Prefix('email', 'admin@')`          |
| `Contains` | Value exists in string/array | `Contains(claim, value)`        | `Contains('roles', 'admin')`         |
| `OneOf`    | Value matches any option     | `OneOf(claim, val1, val2, ...)` | `OneOf('plan', 'pro', 'enterprise')` |

Claim keys and string values may be quoted with single quotes, double quotes or
backticks. A bare literal is accepted for a value, so `Equals('active', true)`
and ``Equals(`active`, `true`)`` mean the same thing.

### Logical Operators

- `!` — NOT (highest precedence)
- `&&` — AND (medium precedence)
- `||` — OR (lowest precedence)

Use parentheses `()` to control evaluation order.

### Expression Examples

```yaml
# Simple validation
claimsExpression: "Equals('active', true)"

# Multiple conditions
claimsExpression: "Equals('email_verified', true) && OneOf('role', 'admin', 'moderator')"

# Complex logic with grouping
claimsExpression: >
  (Contains('organizations', 'acme') || Contains('organizations', 'globex')) &&
  Equals('email_verified', true) &&
  !Equals('suspended', true)
```

## Claim Forwarding

Project verified claims onto the request sent to your upstream services:

```yaml
forward:
  headers:
    X-User-ID: sub                    # Standard claim
    X-User-Email: email               # Standard claim
    X-User-Role: user.role            # Nested claim (dot notation)
    X-Department: profile.department  # Deeply nested claim
    X-Is-Admin: permissions.admin     # Boolean claims become "true"/"false"
    X-User-Roles: roles               # Array claims are joined with ","
    X-User-Name: "{{ .given_name }} {{ .family_name }}"   # Template
  query:
    uid: sub
  cookies:
    app_user: email
```

| Option           | Type    | Description                                                                                          |
|------------------|---------|--------------------------------------------------------------------------------------------------------|
| `headers`        | map     | Header name → claim path or template.                                                                   |
| `query`          | map     | Query parameter → claim path or template.                                                               |
| `cookies`        | map     | Cookie name → claim path or template. Added to the upstream request only, never to the client response. |
| `stripInbound`   | boolean | Remove client-supplied copies of every mapped key. Default `true`.                                      |
| `arraySeparator` | string  | Joins array claims. Default `,`.                                                                        |
| `encoding`       | string  | `auto` (default) base64-encodes non-ASCII values and flags them with a `<Header>-Encoding` companion header; `raw` passes them through. |
| `maxValueBytes`  | int     | Bounds a single projected value. Default `4096`.                                                        |

Every mapped key is removed from the incoming request before the verified value
is set, on every path of the route — including the ones this middleware does not
guard. Without that, a client could send `X-User-Email: admin@example.com` and
your backend would believe it. Set `stripInbound: false` only when nothing but
the gateway can reach the upstream.

Control characters are always removed from forwarded values, so a claim a user
can set for themselves cannot inject a second header into the proxied request.

The deprecated flat `forwardHeaders` map still works and is merged into
`forward.headers`, which takes precedence key by key. The same claim path syntax
is used by the [OpenID Connect middleware](oidc.md).

## Complete Examples

### Basic Authentication

```yaml
middlewares:
  - name: simple-jwt
    type: jwtAuth
    paths: ["/api/.*"]
    rule:
      secret: "your-256-bit-secret"
      algorithms: ["HS256"]
      issuer: "https://your-auth-service.com"
```

### Enterprise Setup with OIDC

```yaml
middlewares:
  - name: enterprise-jwt
    type: jwtAuth
    paths: ["/.*"]
    rule:
      jwksUrl: "https://auth.company.com/.well-known/jwks.json"
      issuer: "https://auth.company.com"
      audience: "api.company.com"
      algorithms: ["RS256"]
      forwardAuthorization: false
      claimsExpression: >
        Equals('email_verified', true) &&
        OneOf('department', 'engineering', 'product', 'security') &&
        !Equals('account_disabled', true)
      forward:
        headers:
          X-User-ID: sub
          X-User-Email: email
          X-User-Name: name
          X-User-Department: department
          X-User-Roles: roles
```

### Multi-Tenant SaaS

```yaml
middlewares:
  - name: tenant-jwt
    type: jwtAuth
    paths: ["/tenant/.*/api/.*"]
    rule:
      publicKey: "/etc/ssl/jwt-public.pem"
      algorithms: ["RS256"]
      claimsExpression: >
        Equals('email_verified', true) &&
        Contains('scopes', 'api:read') &&
        OneOf('tenant_role', 'admin', 'user', 'viewer')
      forward:
        headers:
          X-Tenant-ID: tenant_id
          X-User-Role: tenant_role
          X-Permissions: scopes
```