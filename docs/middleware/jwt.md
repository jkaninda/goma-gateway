---
title: JWT
layout: default
parent: Middleware
nav_order: 13
---

# JWT Middleware

The **JWT Middleware** validates JSON Web Tokens (JWT) in incoming requests based on your configuration. It ensures that only requests with a valid authorization token are forwarded to upstream services.

The middleware supports validation using one of the following:

* **Shared Secret**
* **Public Key**
* **JWKS URL**
* **JWKS File**

> ⚠️ **Required**: You must specify **one** of: `secret`, `publicKey`, `jwksUrl`, or `jwksFile`.

---

## Configuration Options

| Option                              | Description                                                                         |
|-------------------------------------|-------------------------------------------------------------------------------------|
| `secret`                            | Shared secret key for HMAC algorithms (e.g., HS256).                                |
| `publicKey`                         | PEM-formatted public key content, a path to a PEM file, or a base64-encoded key.    |
| `jwksFile`                          | File path or content (raw or base64) of a JWKS (JSON Web Key Set).                  |
| `jwksUrl`                           | URL of a JWKS endpoint to dynamically fetch public keys.                            |
| `algo` *(optional)*                 | Expected JWT algorithm (e.g., `RS256`, `HS512`). Recommended for enhanced security. |
| `issuer` *(optional)*               | Expected value of the `iss` claim.                                                  |
| `audience` *(optional)*             | Expected value of the `aud` claim.                                                  |
| `claimsExpression` *(optional)*     | Boolean expression for validating claims using logical operators and functions.     |
| `forwardHeaders` *(optional)*       | Map of claim names to custom headers (supports dot notation for nested claims).     |
| `forwardAuthorization` *(optional)* | Boolean indicating whether to forward the `Authorization` header upstream.          |

---

## Example Configurations

### Minimal Example (Using a Shared Secret)

```yaml
middlewares:
  - name: jwt
    type: jwt
    paths: ["/*"]
    rule:
      secret: MgsEUFgn9xiMym9Lo9rcRUa3wJbQBo...
      algo: "HS256"  # Optional but recommended
```

### Advanced Example (Using Claims Expression, Public Key, JWKS, and Header Forwarding)

```yaml
middlewares:
  - name: jwt
    type: jwt
    paths: ["/*"]
    rule:
      publicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqh..."
      jwksUrl: "https://example.com/.well-known/jwks.json"
      issuer: "https://issuer.example.com"
      algo: "RS256"
      forwardAuthorization: false
      claimsExpression: >
        Equals(`email_verified`, `true`) &&
        OneOf(`user.role`, `admin`, `owner`) &&
        Contains(`tags`, `vip`, `premium`, `gold`)
      forwardHeaders:
        Role: role
        Email: user.profile.email
```

---

## Claims Expression Functions

These functions can be used in the `claimsExpression` field to implement complex claim validation logic.

| Function   | Description                                          | Example                               |
|------------|------------------------------------------------------|---------------------------------------|
| `Equals`   | Checks for an exact match (supports bools/numbers)   | `Equals(`active`, true)`              |
| `Prefix`   | Validates that a string starts with a value          | `Prefix(`email`, "admin@")`           |
| `Contains` | Checks if a value exists in a string or array        | `Contains(`tags`, "vip")`             |
| `OneOf`    | Matches if the claim equals one of the listed values | `OneOf(`role`, "admin", "moderator")` |


### Logical Operators

You can use the following logical operators to combine multiple expressions in `claimsExpression`:

* `!` — NOT
* `&&` — AND (evaluated before OR)
* `||` — OR (evaluated after AND)

**Use parentheses to group expressions and control precedence:**

```text
(Contains(`org`, "acme") || Contains(`org`, "globex")) && Equals(`email_verified`, true)
```





