---
title: Route
layout: default
parent: Operator Manual
nav_order: 4
---

# Route

A **Route** defines how the gateway forwards traffic to a backend. Each route attaches to one or more `Gateway` CRs and may apply any number of `Middleware` CRs.

- **API group:** `gateway.jkaninda.dev`
- **Version:** `v1alpha1`
- **Kind:** `Route`

When the `goma-k8s-provider` sidecar is enabled (default), changes to `Route` resources are hot-reloaded into the gateway without a pod restart.

## Minimal example

A single backend, host-based routing, attached to a Gateway named `gateway`:

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Route
metadata:
  name: api
  namespace: default
spec:
  gateways:
    - gateway
  path: /
  hosts:
    - api.example.com
  target: http://api-service.default.svc.cluster.local:8080
  methods:
    - GET
    - POST
```

## Load-balanced backends

Use `backends` instead of `target` to distribute traffic across multiple endpoints. Active health checks remove unhealthy backends from rotation.

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Route
metadata:
  name: api-lb
spec:
  gateways:
    - gateway
  path: /api
  rewrite: /
  hosts:
    - api.example.com
  backends:
    # 80/20 weighted split between v1 and v2.
    - endpoint: http://api-v1.default.svc.cluster.local:8080
      weight: 80
    - endpoint: http://api-v2.default.svc.cluster.local:8080
      weight: 20
    # Canary backend — only receives traffic carrying X-Canary: true.
    # `exclusive: true` keeps it out of the general LB pool.
    - endpoint: http://api-canary.default.svc.cluster.local:8080
      exclusive: true
      match:
        - source: header
          name: X-Canary
          operator: equals
          value: "true"
  healthCheck:
    path: /healthz
    interval: 15s
    timeout: 3s
    healthyStatuses: [200, 204]
```

### Backend matching

`match` rules pin requests to a specific backend based on request attributes. Sources: `header`, `cookie`, `query`, `ip`. Operators: `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`, `in`.

When `exclusive: true`, the backend only receives matched traffic. When `false` (default), matched traffic is pinned but the backend still participates in normal load balancing.

## Per-route TLS

Serve a custom certificate for the route's hosts. Reference a `kubernetes.io/tls` Secret:

```yaml
spec:
  hosts:
    - api.example.com
  tls:
    secretName: api-example-com-tls
```

When the K8s provider sidecar is enabled, the cert/key are written to disk and hot-reloaded — no pod restart.

For ACME-managed certificates, configure `certManager` on the parent [Gateway](./gateway.md#tls) instead.

## Backend TLS / mTLS

Control how the gateway connects to **backend** servers (separate from the cert it serves to clients):

```yaml
spec:
  security:
    forwardHostHeaders: true
    enableExploitProtection: true       # SQLi / XSS heuristics
    tls:
      insecureSkipVerify: false
      rootCAsSecret: backend-ca         # Secret with custom CA bundle
      clientCertSecret: backend-client  # kubernetes.io/tls secret for mTLS
```

## Maintenance mode

Return a static response instead of proxying to the backend:

```yaml
spec:
  maintenance:
    enabled: true
    status: 503
    body: |
      {"error":"maintenance","message":"Back at 14:00 UTC."}
```

## Attaching middlewares

List `Middleware` CR names by `metadata.name`. They are applied in order:

```yaml
spec:
  middlewares:
    - api-jwt
    - api-rate-limit
```

See the [Middleware documentation](./middlware.md) for the supported types and their configuration.

## Spec reference

| Field | Type | Description |
| --- | --- | --- |
| `gateways` | []string | **Required.** Names of `Gateway` CRs (same namespace) this route attaches to. |
| `path` | string | **Required.** URL path matched by this route. |
| `rewrite` | string | Path rewrite (e.g. `/api` → `/`). |
| `target` | string | Single backend URL. Mutually exclusive with `backends`. |
| `methods` | []string | Allowed HTTP methods (e.g. `GET`, `POST`). Empty = all. |
| `enabled` | bool | Whether the route is active. Default: `true`. |
| `priority` | int | Match order — higher matches first. |
| `hosts` | []string | Hostnames for host-based routing. |
| `backends` | []object | Multiple backends for load balancing (see below). |
| `healthCheck` | object | Active backend health check (see below). |
| `security` | object | Per-route security settings. |
| `middlewares` | []string | Middleware CR names to apply. |
| `disableMetrics` | bool | Suppress Prometheus per-route metrics for this route. |
| `tls` | object | `secretName` of a `kubernetes.io/tls` Secret to serve for the route's hosts. |
| `maintenance` | object | Maintenance mode (see above). |

### `spec.backends[]`

| Field | Type | Description |
| --- | --- | --- |
| `endpoint` | string | Backend URL. |
| `weight` | int | Load-balancing weight. |
| `exclusive` | bool | When `true`, only matched requests reach this backend. |
| `match[].source` | enum | `header`, `cookie`, `query`, `ip`. |
| `match[].name` | string | Header / cookie / query parameter name. |
| `match[].operator` | enum | `equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`, `in`. |
| `match[].value` | string | Comparison value (comma-separated for `in`). |

### `spec.healthCheck`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | string | — | Health check path. |
| `interval` | string | `30s` | Check interval. |
| `timeout` | string | `5s` | Per-check timeout. |
| `healthyStatuses` | []int | — | HTTP statuses considered healthy. |

### `spec.security`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `forwardHostHeaders` | bool | `true` | Forward `X-Forwarded-Host` and related headers. |
| `enableExploitProtection` | bool | `false` | Block common SQLi / XSS patterns. |
| `tls.insecureSkipVerify` | bool | `false` | Skip backend TLS verification (not recommended). |
| `tls.rootCAsSecret` | string | — | Secret with CA bundle for backend TLS. |
| `tls.clientCertSecret` | string | — | `kubernetes.io/tls` Secret for backend mTLS. |

## Status

```sh
kubectl get routes
```

```
NAME   GATEWAYS      PATH   TARGET                                READY   AGE
api    [gateway]     /      http://api.default.svc.cluster.local  true    2m
```

`Ready: true` means the route is valid and synced into the parent Gateway's configuration.
