---
title: Monitoring
layout: default
parent: Monitoring and Performance
nav_order: 1
---


## Monitoring

Goma Gateway offers built-in monitoring capabilities to help you track the **health**, **performance**, and **behavior** of your gateway and its routes. Metrics are exposed in a **Prometheus-compatible** format and can be visualized using tools like **Prometheus** and **Grafana**.

The `monitoring` section in the configuration enables you to control observability features such as Prometheus metrics, readiness/liveness probes, and detailed route health checks.


### Configuration Options

| Key                           | Type       | Default    | Description                                                     |
|-------------------------------|------------|------------|-----------------------------------------------------------------|
| `enableMetrics`               | `bool`     | `false`    | Enables the Prometheus metrics endpoint.                        |
| `metricsPath`                 | `string`   | `/metrics` | Custom path for exposing metrics.                               |
| `enableReadiness`             | `bool`     | `true`     | Enables the `/readyz` readiness probe.                          |
| `enableLiveness`              | `bool`     | `true`     | Enables the `/healthz` liveness probe.                          |
| `enableRouteHealthCheck`      | `bool`     | `false`    | Enables `/healthz/routes` for per-route health checks.          |
| `includeRouteHealthErrors`    | `bool`     | `false`    | If `true`, includes route errors in `/healthz/routes` response. |
| `middleware.metrics`          | `[]string` | `[]`       | Middleware stack applied to the `/metrics` endpoint.            |
| `middleware.routeHealthCheck` | `[]string` | `[]`       | Middleware stack applied to the `/healthz/routes` endpoint.     |

---

### Route-Level Metrics

By default, each route collects metrics. You can opt out of metrics for a specific route by setting:

```yaml
disableMetrics: true
```

---

### Example Monitoring Configuration

```yaml
gateway:
  monitoring:
    enableMetrics: true                  # Enable Prometheus metrics
    metricsPath: /metrics                # Custom metrics path (optional)
    enableReadiness: true               # Enable /readyz endpoint
    enableLiveness: true                # Enable /healthz endpoint
    enableRouteHealthCheck: true        # Enable /healthz/routes
    includeRouteHealthErrors: true      # Include route errors in health checks
    middleware:
      metrics:
        - ldap                          # Middleware for /metrics
      routeHealthCheck:
        - ldap                          # Middleware for /healthz/routes
```

---

### Accessing Metrics

Once configured, metrics are available at:

```
http://<gateway-host>:<port>/metrics
```

You can configure **Prometheus** to scrape this endpoint and use **Grafana** for visualization.

---

### Health Endpoints

In addition to performance metrics, Goma Gateway provides dedicated endpoints to monitor health:

* **Liveness Probe**: `/healthz`
* **Readiness Probe**: `/readyz`
* **Route Health Check**: `/healthz/routes` (if enabled)

All endpoints return structured JSON indicating the current status.

---

### Prometheus Scrape Configuration Example

```yaml
scrape_configs:
  - job_name: "gateway"
    metrics_path: "/metrics"  # Optional, defaults to /metrics
    scheme: http              # Use https if TLS is enabled
    scrape_interval: 15s
    static_configs:
      - targets: ["gateway-host:port"]
        labels:
          application: "goma_gateway"
    basic_auth:               # Optional: enable if your gateway requires authentication
      username: username
      password: password
    tls_config:
      insecure_skip_verify: false
```

---

### Available Metrics

Goma Gateway exposes several Prometheus metrics to monitor the gateway at various levels:

* `gateway_middlewares_count` — Number of registered middlewares.
* `gateway_routes_count` — Number of active routes.
* `gateway_uptime_seconds` — Gateway uptime in seconds.
* `gateway_requests_total` — Total processed requests (method, path, route).
* `http_response_status_total` — HTTP responses by status, method, path, route.
* `http_request_duration_seconds` — Histogram of request latencies.
* `http_request_size_bytes` — Histogram of request sizes.
* And many more...

---

### Grafana Dashboard

A prebuilt **Grafana dashboard** is available to visualize metrics from Goma Gateway.

You can import it using dashboard ID: **`23799`**

#### Dashboard Preview

![Goma Gateway Grafana Dashboard](https://raw.githubusercontent.com/jkaninda/goma-gateway/main/docs/images/goma_gateway_observability_dashboard-23799.png)

---
