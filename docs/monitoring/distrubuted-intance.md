---
title: Distributed instances
layout: default
parent: Monitoring and Performance
nav_order: 4
---


# Distributed instances

Goma Gateway includes built-in support for Redis-based rate limiting, enabling efficient and scalable deployments.

By leveraging Redis, the Gateway ensures high-performance request throttling and distributed rate limiting across multiple instances, making it ideal for modern, cloud-native architectures.

```yaml
version: "1.0"
gateway:
  tlsCertFile: cert.pem
  tlsKeyFile: key.pem
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  logLevel: info
  ## Redis connexion for distributed rate limiting; when using multiple instances | It's optional
  redis:
    addr: redis:6379
    password: password
```

