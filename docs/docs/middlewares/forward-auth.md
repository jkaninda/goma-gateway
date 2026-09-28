---
title: ForwardAuth
sidebar_label: ForwardAuth
sidebar_position: 5
---

# ForwardAuth Middleware

The ForwardAuth middleware delegates authentication and authorization decisions to an external service, enabling centralized access control for your applications. This pattern is particularly useful for implementing Single Sign-On (SSO) and centralized authentication across multiple services.

## Overview

The middleware intercepts incoming requests and forwards them to a designated authentication service. Based on the authentication service's response, it either allows the request to proceed or blocks it with an appropriate error or redirect response.

### Authentication Flow

1. **Request Interception**: The middleware captures incoming requests matching configured paths (all paths of the route when `paths` is omitted)
2. **Forward to Auth Service**: Sends a `GET` request to `authUrl` carrying the original request's details (see [Automatically Forwarded Headers](#automatically-forwarded-headers))
3. **Decision Based on Response**:
    - **200 OK**: Request is authenticated and forwarded to the backend. Any cookies set by the auth service are added to the client response
    - **401**: Redirects to `authSignIn` with `302 Found` when it is set; otherwise responds `401`
    - **403**: Responds `403`
    - **Other codes**: Responds `401`
    - **Auth service unreachable**: Responds `500`

A `WWW-Authenticate` header returned by the auth service is relayed to the client
on a denied request.

## Configuration

### Basic Configuration

```yaml
middlewares:
  - name: forward-auth
    type: forwardAuth
    paths:
      - /admin
    rule:
      authUrl: http://auth-service:8080/verify
```

### Configuration Parameters

| Parameter                     | Type    | Required | Default     | Description                                                                                                                                                     |
|-------------------------------|---------|----------|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `authUrl`                     | string  | Yes      | -           | URL of the authentication service endpoint                                                                                                                      |
| `authSignIn`                  | string  | No       | -           | Redirect URL for unauthenticated users (401 responses).<br/> If the URL contains a `?` (e.g. `?rd=`), the URL-encoded current request URL is appended to it |
| `insecureSkipVerify`          | boolean | No       | `false`     | Skip SSL certificate verification for auth service                                                                                                              |
| `forwardHostHeaders`          | boolean | No       | `false`     | Send the auth request with the original request's `Host` instead of the `authUrl` host                                                                          |
| `authRequestHeaders`          | array   | No       | `[]`        | Additional request headers to copy to the auth request (`Authorization` and all cookies are always copied)                                                     |
| `addAuthCookiesToResponse`    | array   | No       | -           | Currently has no effect: every cookie set by the auth service on a `200` response is added to the client response                                               |
| `authResponseHeaders`         | array   | No       | `[]`        | Auth response headers to copy onto the upstream request                                                                                                         |
| `authResponseHeadersAsParams` | array   | No       | `[]`        | Auth response headers to copy onto the upstream request as query parameters                                                                                     |

`enableHostForwarding` and `skipInsecureVerify` were removed in v1.0; use
`forwardHostHeaders` and `insecureSkipVerify`.

### Path Configuration

`paths` entries are regular expressions matched from the start of the path, for
example `/admin`, `/admin/.*` or `/api/v[0-9]+/.*`. See
[Path patterns](overview.md#path-patterns).

## Automatically Forwarded Headers

The middleware automatically includes these headers in authentication requests:

- `X-Forwarded-Host` - Original request host
- `X-Forwarded-Method` - HTTP method of original request
- `X-Forwarded-Proto` - Protocol (http/https) of original request
- `X-Forwarded-For` - Client IP address chain
- `X-Real-IP` - Real client IP address
- `User-Agent` - Client user agent string
- `X-Original-URL` - Complete original request URL
- `X-Forwarded-URI` - Complete original request URL (same value as `X-Original-URL`)
- `Authorization` - When present on the original request
- All cookies of the original request

## Advanced Configuration Examples

### Complete ForwardAuth Setup

```yaml
middlewares:
  - name: comprehensive-auth
    type: forwardAuth
    paths:
      - /admin/.*
      - /api/private/.*
    rule:
      authUrl: http://auth-service:8080/auth/verify
      # Redirect URL - current URL automatically appended to 'redirect=' parameter
      authSignIn: http://auth-service:8080/login?redirect=
      insecureSkipVerify: false
      forwardHostHeaders: true
      
      # Include specific headers in auth requests
      authRequestHeaders:
        - Authorization
        - X-API-Key
        - X-Client-Version
      
      # Map auth service headers to request headers
      authResponseHeaders:
        - "x-user-id: X-Auth-User-ID"        # Custom mapping
        - "x-user-roles: X-Auth-Roles"       # Custom mapping  
        - X-Auth-Email                       # Direct mapping
      
      # Add auth headers as request parameters
      authResponseHeadersAsParams:
        - "x-user-id: userId"                # Custom parameter name
        - "x-user-roles: userRoles"          # Custom parameter name
        - X-Auth-Email                       # Direct mapping
```

### Authentik Integration Example

```yaml
version: 2
gateway:
  routes:
    # Protected application route
    - path: /
      name: protected-app
      backends:
        - endpoint: https://internal-app.example.com
      middlewares:
        - authentik-forward-auth
    
    # Authentik outpost route (must be unprotected)
    - path: /outpost.goauthentik.io
      name: authentik-outpost
      backends:
        - endpoint: http://authentik-outpost:9000
      middlewares: []  # No auth middleware for outpost endpoints

middlewares:
  - name: authentik-forward-auth
    type: forwardAuth
    rule:
      authUrl: http://authentik:9000/outpost.goauthentik.io/auth/nginx
      # Public sign-in URL; the current URL is appended to 'rd='
      authSignIn: https://app.example.com/outpost.goauthentik.io/start?rd=
      forwardHostHeaders: true
      insecureSkipVerify: false

      # Include Authentik user information in requests
      authResponseHeaders:
        - X-authentik-username
        - X-authentik-groups
        - X-authentik-email
        - X-authentik-name
        - X-authentik-uid
        - X-authentik-jwt
```

`middlewares` is a top-level key, not a child of `gateway`.

### Development Environment Setup

```yaml
middlewares:
  - name: dev-auth
    type: forwardAuth
    paths:
      - /admin/.*
    rule:
      authUrl: https://dev-auth.local:8443/verify
      authSignIn: https://dev-auth.local:8443/login?next=
      insecureSkipVerify: true  # OK for development only
      forwardHostHeaders: true
      
      authRequestHeaders:
        - Authorization
        - X-Debug-User
      
      authResponseHeaders:
        - "x-dev-user: X-Auth-User"
        - X-Auth-Roles
```

## Header Mapping Syntax

### Direct Mapping
When no custom mapping is specified, headers are passed through directly:
```yaml
authResponseHeaders:
  - X-User-ID      # Auth service header X-User-ID → Request header X-User-ID
  - X-User-Roles   # Auth service header X-User-Roles → Request header X-User-Roles
```

### Custom Mapping
Use colon syntax to map auth service headers to different request header names:
```yaml
authResponseHeaders:
  - "auth-user-id: X-Current-User"     # auth-user-id → X-Current-User
  - "auth-permissions: X-User-Perms"   # auth-permissions → X-User-Perms
```

### Parameter Mapping
Similar syntax applies to parameter mappings:
```yaml
authResponseHeadersAsParams:
  - "X-User-ID: currentUserId"         # Header X-User-ID → Parameter currentUserId
  - "X-User-Roles: roles"              # Header X-User-Roles → Parameter roles
  - X-User-Email                       # Header X-User-Email → Parameter X-User-Email
```

## Authentication Service Requirements

### Response Codes
Your authentication service should return:
- **200 OK**: User is authenticated and authorized (other 2xx codes are treated as a denial)
- **401 Unauthorized**: User is not authenticated (triggers redirect if `authSignIn` configured)
- **403 Forbidden**: User is authenticated but not authorized for this resource
- **Other codes**: Access denied with `401`

### Expected Headers
The auth service receives forwarded headers and can use them for decision-making:
- Use `X-Original-URL` for path-based authorization
- Use `X-Forwarded-Method` for method-based rules
- Use custom headers specified in `authRequestHeaders`

### Response Headers
The auth service can include headers in responses that will be:
- Mapped to request headers via `authResponseHeaders`
- Added as request parameters via `authResponseHeadersAsParams`
- Set as cookies on the client response (every `Set-Cookie` of a `200` response)


## Security Considerations

### SSL/TLS Configuration
- Always use HTTPS for production authentication services
- Set `insecureSkipVerify: false` in production environments
- Use proper SSL certificates to prevent man-in-the-middle attacks

### Header Security
- Every header named in `authResponseHeaders` and every parameter named in
  `authResponseHeadersAsParams` is removed from the incoming request on all
  paths of the route, so a client cannot supply its own identity headers
- Validate and sanitize headers in your authentication service
- Be cautious about which headers you forward to backend services
- Consider header injection risks when mapping auth response headers

### Redirect Security
- Validate redirect URLs to prevent open redirect vulnerabilities
- Use allowlisted domains for `authSignIn` URLs
- Consider implementing CSRF protection for authentication flows

## Troubleshooting

### Common Issues

**Authentication loops or repeated redirects**
- Check that auth service endpoints are excluded from protection
- Verify `authSignIn` URL is accessible without authentication
- Ensure auth service doesn't redirect authenticated requests

**Headers not being forwarded**
- Header names are case-insensitive; query parameter names are case-sensitive
- Check that auth service is returning expected headers
- Confirm header mapping syntax is correct

**SSL/Certificate errors**
- Verify SSL certificates are valid and trusted
- Check if `insecureSkipVerify` should be enabled temporarily for debugging
- Ensure auth service is accessible at the configured URL

