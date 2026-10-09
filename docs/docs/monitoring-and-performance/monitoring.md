---
title: Monitoring
sidebar_label: Monitoring
sidebar_position: 1
---


## Monitoring

Goma Gateway offers built-in monitoring capabilities to help you track the **health**, **performance**, and **behavior** of your gateway and its routes. Metrics are exposed in a **Prometheus-compatible** format and can be visualized using tools like **Prometheus** and **Grafana**.

The `gateway.monitoring` section in the configuration enables you to control observability features such as Prometheus metrics, readiness/liveness probes, and detailed route health checks.

:::note[Upgrading from v0.x]
v1.0 removed the top-level `gateway.enableMetrics` key. Use `gateway.monitoring.enableMetrics` instead; see the [v1.0 upgrade notes](../upgrade/v1.0.md#gateway-enablemetrics).
:::


### Configuration Options

| Key                           | Type       | Default    | Description                                                           |
|-------------------------------|------------|------------|-----------------------------------------------------------------------|
| `host`                        | `string`   | `""`       | Restricts the metrics and route health endpoints to a specific hostname. |
| `enableMetrics`               | `bool`     | `false`    | Enables the Prometheus-compatible `/metrics` endpoint.                |
| `metricsPath`                 | `string`   | `/metrics` | Sets a custom path for metrics exposure.                              |
| `visitorTTL`                  | `string`   | `5m`       | How long a visitor keeps counting towards the real-time visitors gauge after their last request (minimum `30s`). |
| `enableReadiness`             | `bool`     | `true`     | Enables the `/readyz` readiness probe endpoint.                       |
| `enableLiveness`              | `bool`     | `true`     | Enables the `/healthz` liveness probe endpoint.                       |
| `enableRouteHealthCheck`      | `bool`     | `false`    | Enables the `/healthz/routes` endpoint for route-level health checks. |
| `includeRouteHealthErrors`    | `bool`     | `false`    | Includes route errors in the `/healthz/routes` response if `true`.    |
| `middleware.metrics`          | `[]string` | `[]`       | Middleware chain applied to the metrics endpoint.                     |
| `middleware.routeHealthCheck` | `[]string` | `[]`       | Middleware chain applied to the route health check endpoint.          |


The metrics endpoint answers `GET` requests on the gateway's regular entry points (`8080` for HTTP and `8443` for HTTPS by default). If neither `host` nor a middleware is set for `/metrics` or `/healthz/routes`, the gateway logs a warning at startup, because the endpoint is then reachable through any host that routes to the gateway.

:::note
`host` does not apply to `/readyz` and `/healthz`, which stay reachable on every host so that load balancers and Kubernetes probes can use them.
:::

`GOMA_ENABLE_METRICS`, `GOMA_ENABLE_READINESS`, and `GOMA_ENABLE_LIVENESS` (`true`/`false`) override `enableMetrics`, `enableReadiness`, and `enableLiveness`.


---

### Route-Level Metrics

When metrics are enabled, each route collects metrics. You can opt out of metrics for a specific route by setting:

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
    visitorTTL: 5m                       # How long a visitor counts as active (optional)
    enableReadiness: true               # Enable /readyz endpoint
    enableLiveness: true                # Enable /healthz endpoint
    enableRouteHealthCheck: true        # Enable /healthz/routes
    includeRouteHealthErrors: true      # Include route errors in health checks
    middleware:
      metrics:
        - ldap-auth                         # Middleware for /metrics
      routeHealthCheck:
        - ldap-auth                          # Middleware for /healthz/routes
```

---

### Accessing Metrics

Once configured, metrics are available at:

```
http://<gateway-host>:8080/metrics
```

Replace `/metrics` with your `metricsPath` if you changed it.

You can configure **Prometheus** to scrape this endpoint and use **Grafana** for visualization.

---

### Health Endpoints

In addition to performance metrics, Goma Gateway provides dedicated endpoints to monitor health:

* **Liveness Probe**: `/healthz`
* **Readiness Probe**: `/readyz`
* **Route Health Check**: `/healthz/routes` (if enabled)

All endpoints return JSON. `/healthz` and `/readyz` report the gateway process itself; `/healthz/routes` runs the [health checks](../usermanual/healthcheck.md) configured on each route and reports every backend as `healthy` or `unhealthy`.

---

### Prometheus Scrape Configuration Example

```yaml
scrape_configs:
  - job_name: "gateway"
    metrics_path: "/metrics"  # Optional, defaults to /metrics
    scheme: http              # Use https if TLS is enabled
    scrape_interval: 15s
    static_configs:
      - targets: ["gateway-host:8080"]
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

Goma Gateway exposes the following Prometheus metrics. The `name` label is the route name.

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gateway_uptime_seconds` | gauge | — | Uptime of the gateway in seconds since startup. |
| `gateway_routes_count` | gauge | — | Current number of registered routes. |
| `gateway_middlewares_count` | gauge | — | Current number of registered middlewares. |
| `gateway_realtime_visitors_count` | gauge | — | Distinct visitors seen within `visitorTTL`. Shared across instances when Redis is configured. |
| `gateway_requests_total` | counter | `name`, `method` | Total requests processed. |
| `gateway_response_status_total` | counter | `status`, `name`, `method` | HTTP responses sent, by status code. |
| `gateway_request_duration_seconds` | histogram | `name`, `method` | Request duration in seconds. |
| `gateway_upstream_duration_seconds` | histogram | `name` | Time spent in the **upstream/backend**. Lets you separate *"my app is slow"* from *"the gateway is slow"* (gateway overhead = request − upstream). |
| `gateway_request_bytes_total` | counter | `name`, `method` | Request body bytes received (from `Content-Length`; bandwidth in). |
| `gateway_response_bytes_total` | counter | `name`, `method` | Response body bytes sent (bandwidth out). |
| `gateway_total_errors_intercepted` | counter | `name`, `status` | Responses replaced by the [error interceptor](../middlewares/error-interceptor.md). |
| `gateway_requests_by_country_total` | counter | `name`, `country` | Requests by client country (ISO code). Only recorded when a GeoIP database is available (`gateway.geoip.database` or `GOMA_GEOIP_DB`). |
| `gateway_backend_ejections_total` | counter | `backend` | Times a backend was taken out of rotation by the [passive health check](load-balancing.md#passive-health-checks). |
| `gateway_geoblock_denied_total` | counter | `name`, `country` | Requests denied by a [`geoBlock`](../middlewares/geo-block.md) middleware; here `name` is the middleware name. |

The endpoint also serves the standard Go runtime (`go_*`) and process (`process_*`) metrics of the Prometheus client library.

> 💡 **Web-performance metrics.** The bandwidth (`*_bytes_total`), upstream-duration, and by-country metrics power per-route traffic, throughput and latency-split views. For per-request data, the gateway can also publish an **event stream** to Redis for an external consumer (such as Miabi) to build traffic and web-analytics dashboards — see [Analytics](./analytics.md).

---

### Profiling (pprof)

Set `GOMA_PPROF_ADDR` to start the standard Go [pprof](https://pkg.go.dev/net/http/pprof) endpoints on a separate listener. Profiling is off when the variable is unset.

```shell
GOMA_PPROF_ADDR=127.0.0.1:6060
```

The endpoints are served under `/debug/pprof/` on that address only, never on the gateway's entry points:

```shell
go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30   # CPU
go tool pprof http://127.0.0.1:6060/debug/pprof/heap                 # memory
curl http://127.0.0.1:6060/debug/pprof/goroutine?debug=1             # goroutines
```

:::warning

The pprof endpoints have no authentication and expose memory contents, command-line arguments and goroutine stacks. Bind to a loopback address such as `127.0.0.1:6060`. An address without a host (`:6060`) or with `0.0.0.0` listens on every interface, and the gateway logs a warning when it does. In a container, reach a loopback listener with `kubectl port-forward` or `docker exec` instead of publishing the port.

:::

---

### Grafana Dashboard

A prebuilt **Grafana dashboard** is available to visualize metrics from Goma Gateway.

You can import it using dashboard ID: [23799](https://grafana.com/grafana/dashboards/23799)

#### Dashboard Preview

![Goma Gateway Grafana Dashboard](https://raw.githubusercontent.com/jkaninda/goma-gateway/main/docs/images/goma_gateway_observability_dashboard-23799.png)

---
