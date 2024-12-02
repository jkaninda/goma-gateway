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
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: basic-middleware-sample
spec:
    type: basic
    paths:
      - /admin/*
    rule:
        username: admin
        password: admin
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
