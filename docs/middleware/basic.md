---
title: Basic auth
layout: default
parent: Middleware
nav_order: 4
---


# Basic Auth Middleware

Basic-auth middleware secures route paths by requiring a username and password for access.

## Key Features
- Rule: To block all subpaths of a route, append /* to the path explicitly.

- Tip: Always test configurations thoroughly in a staging environment before applying them to production.


### Example: Basic-Auth Middleware Configuration
The following example demonstrates how to configure basic-auth middleware:

```yaml
middlewares:
  - name: basic-auth
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
### Explanation:

- `/admin`: Requires authentication for the exact path /admin.
- `/admin/*`: The path /admin and all its subpaths (e.g., /admin/settings) require authentication due to the /* wildcard.
- `rule`: Specifies the users required for authentication.


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

## Advanced Kubernetes deployment

To deploy the basic-auth middleware in a Kubernetes environment, use the following example:

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: basic-middleware-sample
spec:
    type: basic
    paths:
      - /admin  # Explicitly blocks /admin and all subpaths
    rule:
      realm: your-realm # Optional
      users:
        - admin:{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc= # SHA-1 hash
        - admin:$2a$12$LaPhf23UoCGepWqDO0IUPOttStnndA5V8w7XPNeP0vn712N5Uyali # bcrypt hash
        - admin:admin # Plaintext password
```

By following these guidelines, you can effectively use basic-auth middleware to protect your application routes.