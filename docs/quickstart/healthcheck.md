---
title: Healthcheck
layout: default
parent: Quickstart
nav_order: 2
---


# Healthcheck

Goma comes with routes healthcheck, that can be enabled and disabled.


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