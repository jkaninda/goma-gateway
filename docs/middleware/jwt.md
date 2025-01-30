---
title: JWT
layout: default
parent: Middleware
nav_order: 13
---

# JWT Middleware

The **JWT Middleware** is designed to validate JSON Web Tokens (JWT) in incoming requests based on your configuration. It ensures that the provided authorization token is valid before forwarding the request to the backend. The middleware supports validation using a **secret**, a **public key**, or a **JWKS URL**.

---

## Configuration Options

The JWT Middleware can be configured with the following options:

- **`secret`**: A shared secret key used to validate the JWT signature.
- **`publicKey`**: The path to a public key file or the raw content of the public key (in PEM format) used to validate the JWT signature.
- **`jwksUrl`**: The URL of a JSON Web Key Set (JWKS) endpoint. This is used to dynamically fetch public keys for token validation.

---

## Example Configurations

### Minimal Configuration
Below is an example of a minimal JWT authentication configuration using a shared secret:

```yaml
middlewares:
    - name: jwt
      type: jwt
      paths:
        - "/*"
      rule:
        secret: MgsEUFgn9xiMym9Lo9rcRUa3wJbQBo...
```

### Advanced Configuration
For more advanced use cases, you can configure the middleware with additional options such as a `publicKey`, `jwksUrl`, and `forwardAuthorization`:

```yaml
middlewares:
    - name: jwt
      type: jwt
      paths:
        - "/*"
      rule:
        secret: MgsEUFgn9xiMym9Lo9rcRUa3wJbQBo...
        publicKey: "" # File path to the certificate or raw certificate content
        jwksUrl: ""   # URL to fetch JWKS for dynamic key resolution
        forwardAuthorization: false # Whether to forward the Authorization header
```

---

