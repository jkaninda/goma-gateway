---
title: Middleware
layout: default
parent: Operator Manual
nav_order: 3
---

# Middleware

### Basic-auth

A simple example of middleware

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: basic-middleware-sample
spec:
  type: basic
  paths:
    - /admin # Blocks only /admin
    - /admin/*  # Explicitly blocks /admin and all subpaths
  rule:
    realm: your-realm # Optional
    users:
      - admin:{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc= # SHA-1 hash
      - admin:$2a$12$LaPhf23UoCGepWqDO0IUPOttStnndA5V8w7XPNeP0vn712N5Uyali # bcrypt hash
      - admin:admin # Plaintext password
```
---
### ForwardAuth Middleware

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: forwardAuth
spec:
    type: forwardAuth
    paths:
      - /admin # Blocks only /admin
      - /admin/*  # Explicitly blocks /admin and all subpaths
    rule:
      # URL of the backend authentication service
      authUrl: http://authentication-service:8080/auth/verify

      # Redirect URL when response status is 401
      authSignIn: http://authentication-service:8080/auth/signin

      # Skip SSL certificate verification
      skipInsecureVerify: true

      # Forward the original Host header
      enableHostForwarding: true

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
### Access Middleware

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: access-middleware-sample
spec:
    type: access
  ## prevents access paths
    paths:
      - /swagger-ui/*
      - /v2/swagger-ui/*
      - /api-docs/*
      - /internal/*
      - /actuator/*
    rule:
      statusCode: 404 # Custom status code, default 403
```

## OAuth Middleware

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: oauth-middleware-sample
spec:
    type: oauth
    paths:
      - /protected
      - /example-of-oauth
    rule:
      clientId: xxx
      clientSecret: xxx
      # oauth provider google, gitlab, github, amazon, facebook, custom
      provider: custom
      endpoint:
        authUrl: https://authentik.example.com/application/o/authorize/
        tokenUrl: https://authentik.example.com/application/o/token/
        userInfoUrl: https://authentik.example.com/application/o/userinfo/
      redirectUrl: https://example.com/callback
      #RedirectPath is the PATH to redirect users after authentication, e.g: /my-protected-path/dashboard
      redirectPath: ''
      #CookiePath e.g.: /my-protected-path or / || by default is applied on a route path
      cookiePath: "/"
      scopes:
        - email
        - openid
      state: randomStateString
      jwtSecret: your-strong-jwt-secret | It's optional
```
---
## Rate Limiting

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: ratelimit-middleware-sample
spec:
    type: rateLimit
    paths:
      - /*
    rule:
      unit: second # minute or hour
      requestsPerUnit: 60
```