---
title: OAuth auth
layout: default
parent: Middleware
nav_order: 6
---

# OAuth middleware

### Example of Google provider

```yaml
middlewares:
  - name: google-oauth
    type: oauth
    paths:
      - /*
    rule:
      clientId: xxx
      clientSecret: xxxx
      # oauth provider google, gitlab, github, amazon, facebook, custom
      provider: google # facebook, gitlab, github, amazon
      redirectUrl: https://example.com/callback/protected
      #RedirectPath is the PATH to redirect users after authentication, e.g: /my-protected-path/dashboard
      redirectPath: /dashboard
      scopes:
        - https://www.googleapis.com/auth/userinfo.email
        - https://www.googleapis.com/auth/userinfo.profile
      state: randomStateString

```

### Example of Authentik provider

```yaml
middlewares:
    - name: oauth-authentik
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
          jwksUrl: https://authentik.example.com/application/o/goma/jwks/
        redirectUrl: https://example.com/callback # Goma will use the callback path as path
        #RedirectPath is the PATH to redirect users after authentication, e.g: /my-protected-path/dashboard
        redirectPath: ''
        #CookiePath e.g.: /my-protected-path or / || by default is applied on a route path
        cookiePath: "/"
        scopes:
          - email
          - openid
        state: randomStateString
```
### Apply middleware on the route

```yaml
  ##### Define routes
  routes:
    - path: /protected
      name: oauth-route
      rewrite: /
      backends:
       - endpoint: https://example.com
      methods: [POST, PUT, GET]
      healthCheck:
      cors: {}
      middlewares:
        - oauth-authentik
```
