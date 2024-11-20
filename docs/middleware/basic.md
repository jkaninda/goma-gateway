---
title: Basic auth
layout: default
parent: Middleware
nav_order: 3
---


# Basic Auth Middleware


Basic-auth middleware protects route paths.

Example of basic-auth middleware

```yaml
middlewares:
  - name: basic-auth
    type: basic
    paths:
      - /admin/*
    rule:
      username: admin
      password: admin

```
### Apply basic-auth middleware to the route

```yaml
  routes:
    - path: /
      name: Basic-auth
      rewrite: /
      destination: https://example.com
      methods: [POST, PUT, GET]
      healthCheck: {}
      cors: {}
      middlewares:
        - basic-auth
```