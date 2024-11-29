---
title: Access
layout: default
parent: Middleware
nav_order: 2
---


# Access Middleware

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
### Apply access middleware on the route

```yaml
  routes:
    - path: /protected
      name: protected
      rewrite: /
      destination: 'https://example.com'
      methods: [POST, PUT, GET]
      healthCheck:
      cors: {}
      middlewares:
        - api-forbidden-paths
```
## Advanced Kubernetes deployment

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