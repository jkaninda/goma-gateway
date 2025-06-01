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
version: 2
gateway:
  ...
  cors: # Global CORS configuration (overrides global).
    origins:
      - http://localhost:3000
      - https://dev.example.com
    allowedHeaders:
      - Origin
      - Authorization
      - X-Client-Id
      - Content-Type
      - Accept
    headers:
      X-Session-Id: xxx-xxx-xx
      Access-Control-Max-Age: 1728000
    exposeHeaders: []
    maxAge: 1728000
    allowMethods: ["GET","POST"]
    allowCredentials: true
```

### Example: Route Cors Configuration
```yaml
version: 2
gateway:
  ...
  routes:
    - name: example
    path: /
    rewrite: /
    destination: https://api.example.com
    disableHostFording: false
    blockCommonExploits: true
    cors: # Route-specific CORS configuration (overrides global).
        origins:
          - http://localhost:3000
          - https://dev.example.com
        allowedHeaders:
          - Origin
          - Authorization
          - X-Client-Id
          - Content-Type
          - Accept
        headers:
          X-Session-Id: xxx-xxx-xx
          Access-Control-Max-Age: 1728000
        exposeHeaders: []
        maxAge: 1728000
        allowMethods: ["GET","POST"]
        allowCredentials: true
```