---
title: Monitoring
layout: default
parent: Monitoring and Performance
nav_order: 1
---


## Monitoring

Goma Gateway provides built-in monitoring capabilities to help you track system health, performance, and route behavior. Metrics can be exported in a Prometheus-compatible format and easily visualized using tools like **Prometheus** and **Grafana**.

The `monitoring` section allows you to configure observability endpoints for your gateway, including **Prometheus metrics**, **readiness/liveness probes**, and **route-level health checks**.

### Available Options

| Key                           | Type       | Default    | Description                                                             |
|-------------------------------|------------|------------|-------------------------------------------------------------------------|
| `enableMetrics`               | `bool`     | `false`    | Enables the Prometheus metrics endpoint.                                |
| `metricsPath`                 | `string`   | `/metrics` | Sets a custom path for metrics exposure.                                |
| `enableReadiness`             | `bool`     | `true`     | Enables the `/readyz` readiness probe.                                  |
| `enableLiveness`              | `bool`     | `true`     | Enables the `/healthz` liveness probe.                                  |
| `enableRouteHealthCheck`      | `bool`     | `false`    | Enables the `/healthz/routes` endpoint for detailed route-level checks. |
| `includeRouteHealthErrors`    | `bool`     | `false`    | If `true`, includes route errors in the `/healthz/routes` response.     |
| `middleware.metrics`          | `[]string` | `[]`       | Middleware list applied to the `/metrics` endpoint.                     |
| `middleware.routeHealthCheck` | `[]string` | `[]`       | Middleware list applied to the `/healthz/routes` endpoint.              |

---

### Example Configuration

```yaml
gateway:
  monitoring:
    enableMetrics: true                  # Enable Prometheus metrics
    metricsPath: /metrics                # Custom path for metrics (optional)
    enableReadiness: true               # Enable /readyz readiness endpoint
    enableLiveness: true                # Enable /healthz liveness endpoint
    enableRouteHealthCheck: true        # Enable /healthz/routes for route-level checks
    includeRouteHealthErrors: true      # Include route errors in /healthz/routes
    middleware:
      metrics:
        - ldap                          # Middleware for /metrics
      routeHealthCheck:
        - ldap                          # Middleware for /healthz/routes
```

---

### Accessing Metrics

Once configured, metrics will be available at:

```
http://<gateway-host>:<port>/metrics
```

You can configure Prometheus to scrape this endpoint and visualize it via Grafana dashboards.

---

### Health Check Metrics

In addition to core performance metrics (requests, latency, response status codes), Goma Gateway also provides optional health-related data:

* **Route Health Endpoint**: `/healthz/routes`
* **Gateway Health Endpoints**: `/healthz`, `/readyz`

These endpoints return structured JSON data indicating the health status of the gateway and its configured routes.

---

### Example Use Case: Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'goma-gateway'
    static_configs:
      - targets: ['gateway-host:port']
```

