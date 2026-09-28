---
title: Health check
sidebar_label: Health check
sidebar_position: 6
---


## Route Health Checks

Goma Gateway can probe backend services in the background and stop sending traffic to backends that fail. Health checks are configured per route, and their results can also be queried through dedicated monitoring endpoints.

---

### Enabling Route Health Checks

Each route can define its own health check. The gateway sends a `GET` request to the check path on each backend and decides from the HTTP status code whether the backend is healthy.

```yaml
version: 2
gateway:
  routes:
    - name: example-route
      path: /cart
      rewrite: /
      backends:
        - endpoint: http://cart-1:8080
        - endpoint: http://cart-2:8080
      healthCheck:
        path: "/health/live"
        interval: 30s          # Interval between checks
        timeout: 10s           # Timeout for each health check request
        healthyStatuses: [200, 404]  # HTTP status codes considered healthy
```

| Key               | Type     | Default | Description                                                                                          |
|-------------------|----------|---------|------------------------------------------------------------------------------------------------------|
| `path`            | `string` | —       | Path appended to each backend endpoint (or to `target`), joined with a single `/`. Health checks run only when it is set. |
| `interval`        | `string` | `30s`   | Time between checks, as a Go duration (`10s`, `1m`).                                                 |
| `timeout`         | `string` | `10s`   | Timeout for each check request. An invalid value falls back to the default.                         |
| `healthyStatuses` | `[]int`  | `[]`    | Status codes that count as healthy. When empty, any status below `400` is healthy.                   |

How the result is used:

* On a route with several `backends`, a backend that fails one check is removed from load balancing and put back as soon as a check succeeds. See [Load Balancing](../monitoring-and-performance/load-balancing.md).
* On a route with a single backend or only a `target`, failures are logged but requests are still forwarded.
* The first check runs one `interval` after the gateway starts or reloads its configuration.
* Checks reuse the route's `security.tls` settings (`insecureSkipVerify`, and the [backend mTLS](mtls.md#backend-configuration) certificates).

---

## Gateway Health Endpoints

Goma Gateway exposes health endpoints for the gateway process itself and, optionally, for each route.

### Available Endpoints

* **Gateway Health** (enabled by default):

  * `GET /readyz` — Readiness probe. Disable with `monitoring.enableReadiness: false`.
  * `GET /healthz` — Liveness probe. Disable with `monitoring.enableLiveness: false`.

  Both return `200 OK` with the same body as long as the gateway is serving requests.

* **Routes Health** (disabled by default):

  * `GET /healthz/routes` — Runs every route's health check when called and reports the result. Enable it with `monitoring.enableRouteHealthCheck: true`, and restrict it with `monitoring.host` or `monitoring.middleware.routeHealthCheck`. See [Monitoring](gateway.md#monitoring).

---

### Example: `/healthz` Response

```json
{
  "name": "Service Gateway",
  "status": "running",
  "error": ""
}
```

### Example: `/healthz/routes` Response

Routes with several backends report one entry per backend, named `<route> - [<index>]`.

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
      "name": "store-service - [0]",
      "status": "healthy",
      "error": ""
    },
    {
      "name": "store-service - [1]",
      "status": "unhealthy",
      "error": "Error: health check failed with status code 500"
    }
  ]
}
```

:::note
`/healthz/routes` always answers `200 OK`, and the top-level `status` is always `healthy`. Alerting should look at each entry's `status` field rather than at the HTTP status code.
:::

---
