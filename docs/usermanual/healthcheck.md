---
title: Health check
layout: default
parent: User Manual
nav_order: 6
---


# Route Healthcheck

The proxy includes built-in health check routes, which can be easily enabled or disabled based on your requirements.

These routes allow you to monitor the health and availability of your services.

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
            interval: 30s 
            timeout: 10s
            healthyStatuses: [200,404] # Healthy statuses
```
## Goma Gateway Health Checks

Goma Gateway provides the following health check endpoints:
- Gateway Health:
  - `/readyz`
  - `/healthz`
- Routes Health: `/healthz/routes`

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