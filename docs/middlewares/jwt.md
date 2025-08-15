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
    paths: ["/*"]
    rule:
      secret: "your-secret-key-here"
      algo: "HS256"
```

## Authentication Methods

The middleware supports four authentication methods. **You must configure exactly one**:

###  Shared Secret (HMAC)
Use a shared secret key for HMAC algorithms like HS256, HS384, or HS512.

```yaml
rule:
  secret: "MgsEUFgn9xiMym9Lo9rcRUa3wJbQBo..."
  algo: "HS256"
```

###  Public Key (RSA/ECDSA)
Use a PEM-formatted public key for RSA or ECDSA algorithms.

```yaml
rule:
  publicKey: |
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
    -----END PUBLIC KEY-----
  algo: "RS256"
```

You can also provide:
- **File path**: `/path/to/public-key.pem`
- **Base64 encoded key**: `LS0tLS1CRUdJTi...`

### JWKS URL
Dynamically fetch public keys from a JSON Web Key Set endpoint.

```yaml
rule:
  jwksUrl: "https://your-auth-provider.com/.well-known/jwks.json"
  algo: "RS256"
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

| Option      | Type   | Required | Description                                    |
|-------------|--------|----------|------------------------------------------------|
| `secret`    | string | *        | Shared secret for HMAC algorithms              |
| `publicKey` | string | *        | PEM public key (content, file path, or base64) |
| `jwksUrl`   | string | *        | URL to fetch JWKS dynamically                  |
| `jwksFile`  | string | *        | JWKS file path or content                      |
| `algo`      | string | No       | Expected JWT algorithm (highly recommended)    |

**\* One of these four options is required**

### Token Validation

| Option             | Type   | Description                                    | Example                                     |
|--------------------|--------|------------------------------------------------|---------------------------------------------|
| `issuer`           | string | Expected `iss` claim value                     | `"https://auth.example.com"`                |
| `audience`         | string | Expected `aud` claim value                     | `"api.example.com"`                         |
| `claimsExpression` | string | Boolean expression for custom claim validation | See [Claims Validation](#claims-validation) |

### Header Forwarding

| Option                 | Type    | Description                                                              |
|------------------------|---------|--------------------------------------------------------------------------|
| `forwardHeaders`       | map     | Forward JWT claims as HTTP headers to upstream services                  |
| `forwardAuthorization` | boolean | Whether to forward the original `Authorization` header (default: `true`) |

## Claims Validation

Use `claimsExpression` to implement complex validation logic with boolean expressions:

### Available Functions

| Function   | Purpose                      | Syntax                          | Example                              |
|------------|------------------------------|---------------------------------|--------------------------------------|
| `Equals`   | Exact match comparison       | `Equals(claim, value)`          | `Equals('email_verified', true)`     |
| `Prefix`   | String starts with           | `Prefix(claim, prefix)`         | `Prefix('email', 'admin@')`          |
| `Contains` | Value exists in string/array | `Contains(claim, value)`        | `Contains('roles', 'admin')`         |
| `OneOf`    | Value matches any option     | `OneOf(claim, val1, val2, ...)` | `OneOf('plan', 'pro', 'enterprise')` |

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

## Header Forwarding

Forward JWT claims as HTTP headers to your upstream services:

```yaml
forwardHeaders:
  X-User-ID: sub                    # Standard claim
  X-User-Email: email               # Standard claim  
  X-User-Role: user.role            # Nested claim (dot notation)
  X-Department: profile.department  # Deeply nested claim
  X-Is-Admin: permissions.admin     # Boolean claims become "true"/"false"
```

## Complete Examples

### Basic Authentication

```yaml
middlewares:
  - name: simple-jwt
    type: jwtAuth
    paths: ["/api/*"]
    rule:
      secret: "your-256-bit-secret"
      algo: "HS256"
      issuer: "https://your-auth-service.com"
```

### Enterprise Setup with OIDC

```yaml
middlewares:
  - name: enterprise-jwt
    type: jwtAuth
    paths: ["/*"]
    rule:
      jwksUrl: "https://auth.company.com/.well-known/jwks.json"
      issuer: "https://auth.company.com"
      audience: "api.company.com"
      algo: "RS256"
      forwardAuthorization: false
      claimsExpression: >
        Equals('email_verified', true) &&
        OneOf('department', 'engineering', 'product', 'security') &&
        !Equals('account_disabled', true)
      forwardHeaders:
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
    paths: ["/tenant/*/api/*"]
    rule:
      publicKey: "/etc/ssl/jwt-public.pem"
      algo: "RS256"
      claimsExpression: >
        Equals('email_verified', true) &&
        Contains('scopes', 'api:read') &&
        OneOf('tenant_role', 'admin', 'user', 'viewer')
      forwardHeaders:
        X-Tenant-ID: tenant_id
        X-User-Role: tenant_role
        X-Permissions: scopes
```