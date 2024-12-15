---
title: Rate Limiting
layout: default
parent: Middleware
nav_order: 7
---


### RateLimit middleware

The RateLimit middleware helps manage the number of requests that services receive, ensuring fair usage according to specified limits. 

This middleware applies to the entire route, eliminating the need to specify individual path fields.

Example of rate limiting middleware

```yaml
middlewares:
  - name: rate-limit
    type: rateLimit # or ratelimit
    rule:
      unit: minute          # or hour
      requestsPerUnit: 60    # Maximum number of requests per unit of time
```
### Parameters:

- `unit`: The time period used for rate limiting. Can be set to either `minute` or `hour`.
- `requestsPerUnit`: The maximum number of requests allowed per time unit

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