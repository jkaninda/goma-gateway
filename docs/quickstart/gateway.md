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
  sslCertFile: /etc/goma/cert.pem
  sslKeyFile: /etc/goma/key.pem
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  # Rate limiting
  rateLimit: 0
  accessLog: /dev/Stdout
  errorLog: /dev/stderr
  logLevel: info
  ## Add additional routes
  extraRoutes:
    # path
    directory: /etc/goma/extra
    watch: true
  disableRouteHealthCheckError: false
  disableDisplayRouteOnStart: false
  disableKeepAlive: false
  disableHealthCheckStatus: false
  blockCommonExploits: true
  # Intercept backend errors
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
  routes: []
```
## Extra Routes

The Extra Routes feature allows you to define additional routes by using .yml or .yaml files stored in a specified directory.

This approach helps you avoid the complexity of managing all routes in a single file.

When dealing with many routes, maintaining them in one file can quickly become unwieldy. With this feature, you can organize your routes into separate files, making them easier to manage and maintain.

```yaml
version: 1.0
gateway:
  sslCertFile: /etc/goma/cert.pem
  sslKeyFile: /etc/goma/key.pem
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  # Rate limiting
  rateLimit: 0
  accessLog: /dev/Stdout
  errorLog: /dev/stderr
  logLevel: info
  ## Add additional routes
  extraRoutes:
    # path
    directory: /etc/goma/extra
    watch: true
  disableRouteHealthCheckError: false
  disableDisplayRouteOnStart: false
  disableKeepAlive: false
  disableHealthCheckStatus: false
  blockCommonExploits: true
  # Intercept backend errors
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
  routes: []
```