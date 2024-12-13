---
title: Rate Limiting
layout: default
parent: Middleware
nav_order: 7
---


### RateLimit middleware

The RateLimit middleware ensures that services will receive a fair number of requests, and allows one to define what fair is.

Example of rate limiting middleware

```yaml
middlewares:
  - name: rate-limit
    type: rateLimit #or ratelimit
    paths:
      - /*
    rule:
      unit: minute # or hour
      requestsPerUnit: 60
```

Example of route rate limiting middleware

```yaml
version: 0.1.7
gateway:
  routes:
    - name: Example
      rateLimit: 60 # per minute
```

Example of global rate limiting middleware

```yaml
version: 0.1.7
gateway:
  rateLimit: 60 # per minute
  routes:
    - name: Example
```

## Advanced Kubernetes deployment

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: ratelimit-middleware-sample
spec:
    type: rateLimit
    paths:
      - /*
    rule:
      unit: minute # or hour
      requestsPerUnit: 60
```