---
title: Monitoring
layout: default
parent: Monitoring and Performance
nav_order: 1
---


## Monitoring

Goma Gateway provides built-in monitoring capabilities to help you track system health, performance, and route behavior. Metrics can be exported in a Prometheus-compatible format and easily visualized using tools like **Prometheus** and **Grafana**.

---

### Enabling Metrics

To activate metrics collection, set the `enableMetrics` flag to `true` in the `monitoring` section of the configuration. Once enabled, metrics will be exposed at the specified HTTP path (default: `/metrics`).

---

### Example Configuration

```yaml
version: 2
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

