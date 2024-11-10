---
title: Healthcheck
layout: default
parent: Quickstart
nav_order: 5
---


# Healthcheck

Goma comes with routes healthcheck, that can be enabled and disabled.

```yaml
version: 1.0
gateway:
    routes:
        - path: /cart
          name: example route
          rewrite: /
          methods: []
          healthCheck:
            path: "/health/live"
            interval: 30 # in Seconds
            timeout: 10 # in Seconds
            healthyStatuses: [200,404] # Healthy statuses
```

- Goma Gateway healthcheck: `/health/live`
- Routes health check: `health/routes`

### Gateway healthcheck response:

```json
{
  "name": "Service Gateway",
  "status": "healthy",
  "error": ""
}
```
### Routes healthcheck response:

```json
{
  "status": "healthy",
  "routes": [
    {
      "name": "order-service",
      "status": "healthy",
      "error": ""
    },
    {
      "name": "notification-service",
      "status": "healthy",
      "error": ""
    },
    {
      "name": "store-service",
      "status": "healthy",
      "error": ""
    },
    {
      "name": "account-service",
      "status": "healthy",
      "error": ""
    }
  ]
}
```