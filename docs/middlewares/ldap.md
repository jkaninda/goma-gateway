---
title: LDAP auth
layout: default
parent: Middlewares
nav_order: 14
---

# LDAP Middleware

Goma Gateway supports LDAP integration, allowing you to protect routes with Basic Authentication backed by an LDAP server.

## Key Features

* **Built-in rate limiting** to safeguard your LDAP server from excessive requests.
* **Forward username** to the backend service for downstream use.

## Configuration Example

The following example demonstrates how to configure the `ldap-auth` middleware to enable LDAP-based authentication.

```yaml
middlewares:
  - name: ldap-auth
    type: ldap
    paths:
      - /*
    rule:
      forwardUsername: true          # Forward authenticated username to backend
      realm: ldap-auth               # Authentication realm name
      url: ldap://ldap.example.com:389  # LDAP server URL
      baseDN: dc=example,dc=com         # Base Distinguished Name for user search
      bindDN: uid=manager,ou=people,dc=example,dc=com  # Bind DN for LDAP bind user
      bindPass: bind_user_password         # Password for bind DN
      userFilter: "(&(objectclass=person)(memberof=cn=developer,ou=groups,dc=example,dc=com)(uid=%s))" # LDAP user filter with placeholder for username
      startTLS: false                    # Use StartTLS for LDAP connection (optional)
      insecureSkipVerify: true          # Skip TLS certificate verification (optional)
      connPool:                        # Optional LDAP connection pooling config
        size: 10                      # Number of connections in the pool
        burst: 20                     # Maximum burst limit for rate limiting
        ttl: 30s                     # Connection time-to-live duration
```

### Applying the Middleware on a Route

To enable LDAP authentication on a route, include the middleware name under the route’s `middlewares` section:

```yaml
routes:
  - path: /
    name: ldap-auth-route
    rewrite: /
    backends:
      - endpoint: https://api.example.com
    methods: [POST, PUT, GET]
    healthCheck: {}
    cors: {}
    middlewares:
      - ldap-auth
```