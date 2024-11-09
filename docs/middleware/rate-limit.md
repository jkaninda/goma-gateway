---
title: Rate Limit
layout: default
parent: Middleware
nav_order: 6
---


### RateLimit middleware

The RateLimit middleware ensures that services will receive a fair number of requests, and allows one to define what fair is.

Example of global rateLimit middleware

```yaml
version: 0.1.7
gateway:
  # Proxy rate limit, it's In-Memory IP based
  rateLimit: 60 # peer minute
  routes:
    - name: Example
```
