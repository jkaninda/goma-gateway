---
title: Route
layout: default
parent: Operator Manual
nav_order: 4
---

# Route

A simple example of route

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Route
metadata:
  labels: {}
  name: route-sample
spec:
  gateway: gateway-sample
  path: /
  hosts: []
  rewrite: /
  methods:
    - GET
    - POST
    - PUT
  destination: https://example.com
  backends: []
  insecureSkipVerify: false
  healthCheck:
    path: /
    interval: 10s
    timeout: 10s
    healthyStatuses:
      - 200
      - 404
  cors:
    origins: []
    headers: {}
  rateLimit: 15
  disableHostFording: true
  blockCommonExploits: false
  ## Middleware names
  middlewares:
    - basic-middleware-sample
```