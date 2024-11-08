---
title: Middleware
layout: default
nav_order: 4
---


## Middlewares

Middleware is a function executed before (or after) the route callback.

This is a great way to add API authentication checks, or to validate that the user has permission to access the route.

With Goma you can create your middleware based on the type you want and apply it on your routes

Goma Gateway supports :

- Authentication middleware
    - JWT `client authorization based on the result of a request`
    - Basic-Auth
    - OAuth
- Rate limiting middleware
    - In-Memory client IP based
- Access middleware 

### BasicAuth middleware
The BasicAuth middleware grants access to route to authorized users only.

### Configuration Options

You don't need to hash your password (MD5, SHA1, or BCrypt), Goma gateway will handle it.

You need just to provide the username and password

Example of basic-auth middleware
```yaml
middlewares:
  # Middleware name
  - name: basic-auth
    # Middleware type 
    type: basic
    # Paths to apply middleware
    paths:
      - /user
      - /admin
      - /account
    rule:
      username: admin
      password: admin
```

### JWT middleware

As BasicAuth, JWT middleware grants also access to route to authorized users only.
It implements client authorization based on the result of a request.

If the request returns a 200 response code, access is allowed.
If it returns 401 or 403, the access is denied with the corresponding error code. Any other response code returned by the request is considered an error.

It depends on an authentication service on the backend.

It works as  `ngx_http_auth_request_module` on Nginx
```conf
location /private/ {
    auth_request /auth;
    ...
}

location = /auth {
    proxy_pass ...
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
```

You can also get headers from the authentication request result and inject them into the next request header or params.

In case you want to get headers from the authentication service and inject them into the next request headers.

Set the request variable to the given value after the authorization request completes.

Key is authentication request response header Key. Value is the next Request header Key.

```yaml
     headers:
       ## Key Authentication request header key and value is next request header key
       userId: X-Auth-UserId
       userCountryId: X-Auth-UserCountryId
```
The second example, is in case you want to get headers from the authentication request and inject them into the next request parameters.
Key is authentication request response header Key. Value is the next Request parameter Key.

See the example below.

```yaml
      # Key Authentication request header key and value is next request parameter key
     params:
       userId: userId
       userCountryId: countryId
```
Example of JWT middleware
```yaml
middlewares:
   #Enables JWT authorization based on the result of a request and continues the request.
   - name: google-auth
     # jwt authorization based on the result of backend's response and continue the request when the client is authorized
     type: jwt
     # Paths to protect
     paths:
       - /protected-access
       - /example-of-jwt
       #- /* or wildcard path
     rule:
       # This is an example URL
       url: https://www.googleapis.com/auth/userinfo.email
       # Required headers, if not present in the request, the proxy will return 403
       requiredHeaders:
         - Authorization
       #Set the request variable to the given value after the authorization request completes.
       #
       # Add header to the next request from AuthRequest header, depending on your requirements
       # Key is AuthRequest's response header Key, and value is Request's header Key
       # In case you want to get headers from the authentication service and inject them into the next request header or parameters,
       #Set the request variable to the given value after completing the authorization request.
       #
       # Add header to the next request from AuthRequest header, depending on your requirements
       # Key is AuthRequest's response header Key, and value is next request header Key
    # In case you want to get headers from the authentication service and inject them into the next request headers.
     headers:
       userId: X-Auth-UserId
       userCountryId: X-Auth-UserCountryId
       # In case you want to get headers from the Authentication service and inject them to the next request params.
     params:
       userCountryId: countryId
```
### OAuth middleware

Example of Google provider

```yaml
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
      jwtSecret: your-strong-jwt-secret | It's optional

```

Example of Authentik provider

```yaml
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
### Access middleware

Access middleware prevents access to a route or specific route path.

Example of access middleware
```yaml
  # The server will return 403
  - name: api-forbidden-paths
    type: access
    ## prevents access paths
    paths:
      - /swagger-ui/*
      - /v2/swagger-ui/*
      - /api-docs/*
      - /internal/*
      - /actuator/*
```
### RateLimit middleware

The RateLimit middleware ensures that services will receive a fair amount of requests, and allows one to define what fair is.

Example of rateLimit middleware
```yaml

```

### Apply middleware on the route

```yaml
  ##### Define routes
  routes:
    - name: Basic auth
      path: /protected
      rewrite: /
      destination: 'https://example.com'
      methods: [POST, PUT, GET]
      healthCheck:
      cors: {}
      middlewares:
        # Name of middleware
        - basic-auth
        - access
```
