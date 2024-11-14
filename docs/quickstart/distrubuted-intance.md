---
title: Distributed instances
layout: default
parent: Quickstart
nav_order: 5
---


# Distributed instances

```yaml
version: "1.0"
gateway:
  sslCertFile: cert.pem
  sslKeyFile: key.pem
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  rateLimit: 60 # peer minute
  blockCommonExploits: false
  accessLog: /dev/Stdout
  errorLog: /dev/stderr
  logLevel: ''
  ## Redis connexion for distributed rate limiting; when using multiple instances | It's optional
  redis:
    addr: redis:6379
    password: password
```

