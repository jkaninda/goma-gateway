---
title: Gateway
layout: default
parent: Quickstart
nav_order: 1
---

# Gateway

```yaml
version: 1.0
gateway:
  sslCertFile: cert.pem
  sslKeyFile: key.pem
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  # Rate limiting
  rateLimiter: 0
  accessLog: /dev/Stdout
  errorLog: /dev/stderr
  disableRouteHealthCheckError: false
  disableDisplayRouteOnStart: false
  disableKeepAlive: false
  disableHealthCheckStatus: false
  blockCommonExploits: true
  interceptErrors:
    - 500
  cors:
    origins:
      - http://localhost:8080
      - https://example.com
    headers:
      Access-Control-Allow-Credentials: "true"
      Access-Control-Allow-Headers: Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id
      Access-Control-Max-Age: "1728000"
  routes:
```

