---
title: Basic auth
layout: default
parent: Middlewares
nav_order: 4
---


# Basic Auth Middleware

Basic-auth middleware secures route paths by requiring a username and password for access.
It supports multiple authentication methods, including bcrypt, SHA-1, and plaintext passwords.

### Example: Basic-Auth Middleware Configuration
The following example demonstrates how to configure basic-auth middleware:

```yaml
middlewares:
  - name: basic-auth
    type: basic
    paths:
      - /admin  # Explicitly blocks /admin and all subpaths
    rule:
      realm: your-realm # Optional
      forwardUsername: true          # Forward authenticated username to backend
      users:
        - username: admin
          password: "$2y$05$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO" # bcrypt hash
        - username: user1
          password: "{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc=" # SHA-1 hash       
        - username: user2
          password: password # Plaintext password        
        - username: ${USER_NAME}
          password: ${PASSWORD # Environment variable



### Applying Basic-Auth Middleware to a Route
Here’s how to attach the basic-auth middleware to a route:

```yaml
  routes:
    - path: /
      name: Basic-auth
      rewrite: /
      backends:
       - endpoint: https://example.com
      methods: [POST, PUT, GET]
      healthCheck: {}
      cors: {}
      middlewares:
        - basic-auth
```

### Create user and password

```shell
docker run --rm \
  --entrypoint htpasswd \
  httpd:2 -Bbn admin password
```


By following these guidelines, you can effectively use basic-auth middleware to protect your application routes.