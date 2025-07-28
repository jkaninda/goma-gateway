---
title: ForwardAuth
layout: default
parent: Middlewares
nav_order: 5
---

### ForwardAuth Middleware

The **ForwardAuth middleware** delegates authorization to a backend service, determining access based on the service's HTTP response.

---

### How It Works

1. **Authorization Process**
   - The middleware sends incoming requests to the authentication service specified by `authUrl`.
   - The decision to allow or deny access is based on the service's response:
      - **200 (OK)**: Access is granted.
      - **401 (Unauthorized)** or **403 (Forbidden)**:
         - Access is denied, and the response status is returned.
         - If `authSignIn` is configured, the client is redirected to this URL.
      - **Other Response Codes**: Treated as errors, and access is denied.

2. **Backend Dependency**
   - The middleware requires a functioning backend authentication service to process requests and enforce authorization logic.

---

### Key Features

- **`Rule`**: Defines path-matching logic for applying the middleware. To block all subpaths, use `/*` at the end of the path.
- **`AuthUrl`**: The URL of the backend authentication service.
- **`AuthSignIn`**: The redirect URL used when the authentication service returns a `401` status.
  - This is optional and can be omitted if no sign-in URL is required. 
  - To redirect to the current URL after successful authentication, pass it as a query parameter (e.g., http://authentik.company:9000/outpost.goauthentik.io/start?rd=). Goma Gateway will automatically append the current URL to the `rd` query parameter.
- **`insecureSkipVerify`**: If set to `true`, skips SSL certificate verification for the authentication service. This is useful for development or self-signed certificates but should be avoided in production environments.
- **`forwardHostHeaders`**: Forwards the `Host` header from the original request.
- **`AuthRequestHeaders`**: Specifies request headers to copy into the authentication request.
- **`AddAuthCookiesToResponse`**: Adds selected authentication cookies to the response headers. If not specified, all authentication cookies are copied by default.
- **`AuthResponseHeaders`**: Maps headers from the authentication service response to request headers. Custom mappings can be defined using the format `"auth_header: request_header"`.
- **`AuthResponseHeadersAsParams`**: Copies authentication service response headers into request parameters. Custom parameter names can be defined using the format `"header: parameter"`.

### Forwarded headers

The following headers are automatically forwarded:

- `X-Forwarded-Host`
- `X-Forwarded-Method`
- `X-Forwarded-Proto`
- `X-Forwarded-For`
- `X-Real-IP`
- `User-Agent`
- `X-Original-URL`
- `X-Forwarded-URI`

---

### Example Configuration

Below is an example of a complete configuration for the ForwardAuth middleware:

```yaml
middlewares:
  - name: forward-auth
    type: forwardAuth
    paths:
      - /*
    rule:
      # URL of the backend authentication service
      authUrl: http://authentication-service:8080/auth/verify
      
      # Redirect URL when response status is 401
      authSignIn: http://authentication-service:8080/auth/signin?rd=
      
      # Skip SSL certificate verification
      insecureSkipVerify: true
      
      # Forward the original Host header
      forwardHostHeaders: true
      
      # Headers to include in the authentication request
      authRequestHeaders:
        - Authorization
        - X-Auth-UserId
      
      # Authentication cookies to include in the response
      addAuthCookiesToResponse:
        - X-Auth-UserId
        - X-Token
      # Map authentication response headers to request headers
      authResponseHeaders:
        - "auth_userId: X-Auth-UserId" # Custom mapping
        - X-Auth-UserCountryId # Direct mapping
        - X-Token # Direct mapping
      
      # Map authentication response headers to request parameters
      authResponseHeadersAsParams:
        - "X-Auth-UserId: userId" # Custom mapping
        - X-Token:token # Custom mapping
        - X-Auth-UserCountryId # Direct mapping
```

---
### Example  forwardAuth with Authentik

```yaml

version: "1.0"
gateway:
    writeTimeout: 10
    readTimeout: 15
    idleTimeout: 30
    routes:
        - path: /
          name: my-app
          backends:
           - endpoint: https://example.com
          # Protect the route with forwardAuth
          middlewares:
            - example-forward-auth
        - path: /outpost.goauthentik.io
          name: authentik-outpost
          backends:
           - endpoint: http://authentik-outpost:9000
          cors: {}
          # all requests to /outpost.goauthentik.io must be accessible without authentication
          middlewares: []
    middlewares:
        - name: example-forward-auth
          type: forwardAuth
          paths:
            - /admin
          rule:
            authUrl: http://authentik.company:9000:9000/outpost.goauthentik.io/auth/nginx
            # forward 
            authSignIn: http://authentik.company:9000/outpost.goauthentik.io/start?rd=
            # Optional
            authResponseHeaders:
                - X-authentik-username
                - X-authentik-groups
                - X-authentik-email
                - X-authentik-name
                - X-authentik-jwt
            forwardHostHeaders: true
            insecureSkipVerify: false
```

### Notes

- Use the ForwardAuth middleware to delegate access control and protect endpoints effectively.
- Ensure `AuthUrl` and associated configurations align with your backend authentication service's API.
- **Paths**: The `paths` field supports regex patterns for flexible route matching. 
- Test configurations in a secure environment to validate proper integration before deploying to production.