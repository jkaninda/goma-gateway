---
title: Route
layout: default
parent: Operator Manual
nav_order: 4
---

# Route

A simple example of route

```yaml
## Route
apiVersion: gomaproj.github.io/v1beta1
kind: Route
metadata:
  name: route-sample
spec:
  # Name of the associated gateway
  gateway: gateway-sample

  # Route Configuration
  path: / # URL path for the route
  hosts: [] # Optional: Hostnames/domains for routing
  rewrite: / # Rewrite the path (e.g., /store -> /)
  methods:
    - GET
    - POST
    - PUT

  # Backend Configuration
  destination: https://example.com # Primary destination URL
  insecureSkipVerify: false # Skip TLS verification (not recommended)

  # Health Check Settings
  healthCheck:
    path: / # Health check endpoint
    interval: 10s # Check interval
    timeout: 10s # Timeout for health check
    healthyStatuses:
      - 200 # HTTP status codes indicating healthy responses
      - 404

  # Cross-Origin Resource Sharing (CORS) Configuration
  cors:
    origins: [] # Allowed origins
    headers: {} # custom headers
  # Security and Middleware
  disableHostForwarding: true # Disable forwarding of Host headers
  blockCommonExploits: false  # Enable or disable blocking of common exploits
  # List of middleware names
  middlewares:
    - basic-middleware-sample
```