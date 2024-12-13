---
title: Cross-Origin Resource Sharing (CORS)
layout: default
parent: User Manual
nav_order: 4
---


## Cross-Origin Resource Sharing (CORS)

CORS defines policies to enable secure cross-origin interactions.

In Goma Gateway, you can configure CORS in two ways:
- **Global CORS:** Applied at the gateway level, affecting all routes.
- **Route-Specific CORS:** Applied to individual routes for more granular control.

CORS settings allow you to specify permitted origins and custom headers for secure client-server communication.

### Example: Global CORS Configuration

```yaml
version: 1.0
gateway:
  ...
  cors:
    origins:
      - http://localhost:8080
      - https://example.com
    headers:
      Access-Control-Allow-Credentials: "true"
      Access-Control-Allow-Headers: Origin, Authorization, Accept, Content-Type, X-Client-Id
      Access-Control-Max-Age: "1728000"
      Access-Control-Allow-Origin: "*"
```

### Example: Route Cors Configuration
```yaml
version: 1.0
gateway:
  ...
  routes:
    - name: example
    path: /
    rewrite: /
    destination: https://api.example.com
    disableHostFording: false
    blockCommonExploits: true
    cors:
      origins:
        - http://localhost:8080
        - https://example.com
      headers:
        Access-Control-Allow-Credentials: "true"
        Access-Control-Allow-Headers: Origin, Authorization, Accept, Content-Type
        Access-Control-Max-Age: "1728000"
```