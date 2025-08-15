---
title: ForwardAuth
layout: default
parent: Middlewares
nav_order: 5
---

# ForwardAuth Middleware

The ForwardAuth middleware delegates authentication and authorization decisions to an external service, enabling centralized access control for your applications. This pattern is particularly useful for implementing Single Sign-On (SSO) and centralized authentication across multiple services.

## Overview

The middleware intercepts incoming requests and forwards them to a designated authentication service. Based on the authentication service's response, it either allows the request to proceed or blocks it with an appropriate error or redirect response.

### Authentication Flow

1. **Request Interception**: The middleware captures incoming requests matching configured paths
2. **Forward to Auth Service**: Sends the request details to the configured authentication service
3. **Decision Based on Response**:
    - **200 OK**: Request is authenticated and forwarded to the backend
    - **401/403**: Access denied, optionally redirects to sign-in page
    - **Other codes**: Treated as authentication errors, access denied

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
| `authSignIn`                  | string  | No       | -           | Redirect URL for unauthenticated users (401 responses).<br/> If URL ends with a query parameter (e.g., ?rd=), the current request URL is automatically appended |
| `insecureSkipVerify`          | boolean | No       | `false`     | Skip SSL certificate verification for auth service                                                                                                              |
| `forwardHostHeaders`          | boolean | No       | `false`     | Forward the original `Host` header to auth service                                                                                                              |
| `authRequestHeaders`          | array   | No       | `[]`        | Request headers to include in auth requests                                                                                                                     |
| `addAuthCookiesToResponse`    | array   | No       | all cookies | Auth cookies to include in response headers                                                                                                                     |
| `authResponseHeaders`         | array   | No       | `[]`        | Map auth response headers to request headers                                                                                                                    |
| `authResponseHeadersAsParams` | array   | No       | `[]`        | Map auth response headers to request parameters                                                                                                                 |

### Path Configuration

The `paths` field supports flexible pattern matching:

- **Exact paths**: `/admin`, `/api/users`
- **Wildcard patterns**: `/admin/*`, `/api/*/users`
- **Regex patterns**: `/api/v[0-9]+/.*`

## Automatically Forwarded Headers

The middleware automatically includes these headers in authentication requests:

- `X-Forwarded-Host` - Original request host
- `X-Forwarded-Method` - HTTP method of original request
- `X-Forwarded-Proto` - Protocol (http/https) of original request
- `X-Forwarded-For` - Client IP address chain
- `X-Real-IP` - Real client IP address
- `User-Agent` - Client user agent string
- `X-Original-URL` - Complete original request URL
- `X-Forwarded-URI` - Original request URI

## Advanced Configuration Examples

### Complete ForwardAuth Setup

```yaml
middlewares:
  - name: comprehensive-auth
    type: forwardAuth
    paths:
      - /admin/*
      - /api/private/*
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
      
      # Control which auth cookies are returned
      addAuthCookiesToResponse:
        - session_id
        - auth_token
      
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
version: "1.0"
gateway:
  writeTimeout: 10
  readTimeout: 15
  idleTimeout: 30
  
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
      paths:
        - /admin
      rule:
        authUrl: http://authentik:9000/outpost.goauthentik.io/auth/nginx
        # Redirect URL - current URI automatically appended to 'rd=' parameter
        authSignIn: http://authentik:9000/outpost.goauthentik.io/start?rd=
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

### Development Environment Setup

```yaml
middlewares:
  - name: dev-auth
    type: forwardAuth
    paths:
      - /admin/*
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
- **200 OK**: User is authenticated and authorized
- **401 Unauthorized**: User is not authenticated (triggers redirect if `authSignIn` configured)
- **403 Forbidden**: User is authenticated but not authorized for this resource
- **Other codes**: Treated as errors, access denied

### Expected Headers
The auth service receives forwarded headers and can use them for decision-making:
- Use `X-Original-URL` for path-based authorization
- Use `X-Forwarded-Method` for method-based rules
- Use custom headers specified in `authRequestHeaders`

### Response Headers
The auth service can include headers in responses that will be:
- Mapped to request headers via `authResponseHeaders`
- Added as request parameters via `authResponseHeadersAsParams`
- Set as cookies via `addAuthCookiesToResponse`


## Security Considerations

### SSL/TLS Configuration
- Always use HTTPS for production authentication services
- Set `insecureSkipVerify: false` in production environments
- Use proper SSL certificates to prevent man-in-the-middle attacks

### Header Security
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
- Verify header names match exactly (case-sensitive)
- Check that auth service is returning expected headers
- Confirm header mapping syntax is correct

**SSL/Certificate errors**
- Verify SSL certificates are valid and trusted
- Check if `insecureSkipVerify` should be enabled temporarily for debugging
- Ensure auth service is accessible at the configured URL

