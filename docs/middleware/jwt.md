---
title: JWT auth
layout: default
parent: Middleware
nav_order: 4
---


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
       url: https://www.example.com/auth/access
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