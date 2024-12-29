---
title: JWT Middleware
layout: default
parent: Middleware
nav_order: 5
---


### JWT Middleware

The JWT middleware restricts access to routes, similar to BasicAuth, by authorizing users based on JSON Web Tokens (JWTs).

---

#### How It Works

1. **Authorization Logic**  
   The middleware determines access based on the HTTP response from an authentication service:
   - **200 (OK)**: Access is granted.
   - **401 (Unauthorized)** or **403 (Forbidden)**: Access is denied with the corresponding error code.
   - **Other Response Codes**: Treated as errors.

2. **Backend Dependency**  
   The middleware relies on a backend authentication service to validate requests.

3. **Nginx Inspiration**  
   Its behavior is comparable to `ngx_http_auth_request_module` in Nginx.

### Key Features
- `Rule`: To block all subpaths of a route, append /* to the path explicitly.
- `Header Mapping`: Map headers between authentication response and backend request to customize the data flow.
- `Parameter Mapping`: Map query parameters between authentication response and backend request to customize the data flow.
- `Environment Testing`: Always test configurations in a staging environment before deploying to production.

Here's an example Nginx configuration:

```
   location /private/ {
       auth_request /auth;
       ...
   }

   location = /auth {
       proxy_pass ...;
       proxy_pass_request_body off;
       proxy_set_header Content-Length "";
       proxy_set_header X-Original-URI $request_uri;
   }
```

### Header and Parameter Injection

The middleware supports extracting headers from the authentication response and injecting them into the next request’s headers or parameters.

1. **Injecting Headers**
   Add headers to the next request after a successful authorization:

```yaml
headers:
   # Key: Auth response header key | Value: Next request header key
   userId: X-Auth-UserId
   userCountryId: X-Auth-UserCountryId
```

2. **Injecting Parameters**

Add parameters to the next request from the authentication response headers:

```yaml
params:
   # Key: Auth response header key | Value: Next request parameter key
   userId: userId
   userCountryId: countryId
```

### Example Configuration

Below is a complete example of JWT middleware configuration:

```yaml
middlewares:
   - name: jwt-auth
     type: jwt
      # Paths to protect
     paths:
        - /admin/*
        - /account/*
        # - /* for wildcard paths
     rule:
        # URL of the backend authentication service
        url: https://www.example.com/auth/access
        # Headers required in the incoming request
        requiredHeaders:
           - Authorization
        # Headers to include in the next request
        headers:
           userId: X-Auth-UserId
           userCountryId: X-Auth-UserCountryId
        # Parameters to include in the next request
        params:
           userId: userId
           userCountryId: countryId

```

### Notes

- Use this middleware to secure endpoints by delegating authorization to a backend service.
- Properly configure the rule section to match your authentication service requirements.