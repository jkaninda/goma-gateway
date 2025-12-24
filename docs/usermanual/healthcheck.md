---
title: Health check
layout: default
parent: User Manual
nav_order: 6
---


## Route Health Checks

Goma Gateway supports built-in health check mechanisms to monitor the availability and responsiveness of backend services. Health checks can be configured per route and are also exposed through dedicated endpoints for monitoring.

---

### Enabling Route Health Checks

Each route can define its own health check configuration to determine whether a backend is healthy based on HTTP status codes.

```yaml
version: 2
gateway:
  routes:
    - name: example route
      path: /cart
      rewrite: /
      methods: []
      healthCheck:
        path: "/health/live"
        interval: 30s          # Interval between checks
        timeout: 10s           # Timeout for each health check request
        healthyStatuses: [200, 404]  # HTTP status codes considered healthy
```

>  Use this to automatically detect and skip unhealthy backends when routing traffic.

---

## Gateway Health Endpoints

Goma Gateway exposes health check endpoints for overall system status as well as detailed per-route health.

### Available Endpoints

* **Gateway Health:**

  * `GET /readyz` — Reports if the Gateway is ready to serve traffic.
  * `GET /healthz` — General health status of the Gateway.

* **Routes Health:**

  * `GET /healthz/routes` — Reports the health of all configured routes and their associated backends.

---

### Example: `/healthz` Response

```json
{
  "name": "Service Gateway",
  "status": "healthy",
  "error": ""
}
```

### Example: `/healthz/routes` Response

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

> 💡 If a route becomes unhealthy, its error field will contain diagnostic information.

---
