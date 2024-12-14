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
### Middleware Configuration
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: basic-middleware-sample
spec:
  type: basic # Type of middleware (e.g., basic, jwt, etc.)
  paths:
    - /admin/* # Paths requiring authentication
  rule:
    username: admin # Basic auth username
    password: admin # Basic auth password
```
### JWT-auth

```yaml

```

### Access

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
```
## OAuth2

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
      unit: minute # or hour
      requestsPerUnit: 60
```