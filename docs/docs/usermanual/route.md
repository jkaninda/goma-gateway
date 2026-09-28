---
title: Route
sidebar_label: Route
sidebar_position: 2
---


# Route

A **Route** defines how incoming HTTP traffic is matched and forwarded to backend services. It supports path and host matching, request rewriting, method filtering, health checks, load balancing, middleware, and more.

---

## Configuration Options

Below are the configuration options for defining routes in Goma Gateway:

### Basic Route Options

* **`name`** (`string`, required): Unique name for the route.
* **`path`** (`string`, required): Path prefix to match (e.g., `/api/v1/resource`). The route also serves every path beneath it.
* **`enabled`** (`boolean`, default: `true`): Set to `false` to disable the route.
* **`hosts`** (`[]string`): Optional list of hostnames the route matches.
* **`rewrite`** (`string`): Rewrites the request path before forwarding.

  > For advanced rewriting (regex-based), consider using the [`rewriteRegex`](../middlewares/rewrite-regex.md) middleware.
* **`methods`** (`[]string`): Allowed HTTP methods (e.g., `GET`, `POST`). Defaults to all if omitted.
* **`target`** (`string`): Single backend URL. Ignored when `backends` is set.
* **`backends`** (`[]Backend`): List of backend endpoints for load balancing. A route needs `target` or `backends`.
* **`healthCheck`**: Periodic backend health checks. See [below](#health-check-configuration).
* **`middlewares`** (`[]string`): Names of the middlewares applied to the route, in order.
* **`security`**: Per-route security configuration. See [below](#security-configuration).
* **`tls`**: Per-route TLS settings. See [below](#tls-configuration).
* **`maintenance`**: Returns a fixed response instead of forwarding. See [Maintenance Mode](maintenance-mode.md).
* **`priority`** (`int`, default: `0`): Matching order among routes whose paths both match a request. Lower values take precedence.
* **`disableMetrics`** (`boolean`): If `true`, disables metrics collection for this route.

### Backend Options

Each entry in `backends` accepts:

* **`endpoint`** (`string`): Backend URL.
* **`weight`** (`int`): Weight for weighted load balancing. Without weights, backends are used round-robin.
* **`match`**, **`exclusive`**, **`priority`**: Canary routing rules. See [Canary Deployment](canary-deployment.md).

See also [Load Balancing](../monitoring-and-performance/load-balancing.md).

## Minimal Route Configuration

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /cart
      target: http://cart-service:8080
```

---

## Health Check Configuration

Configure periodic health checks for route backends:

```yaml
healthCheck:
  path: "/health"
  interval: 30s      # Default: 30s
  timeout: 10s
  healthyStatuses: [200, 404]
```

* **`path`** (`string`): URL path used for health checks. Health checks run only when it is set.
* **`interval`** (`duration`): How frequently to check. Default: `30s`.
* **`timeout`** (`duration`): Timeout for the health check request. Default: `10s`.
* **`healthyStatuses`** (`[]int`): List of HTTP status codes considered healthy. If omitted, any status below `400` is healthy.

See [Health check](healthcheck.md) for the `/healthz/routes` endpoint.

---

## Security Configuration

Control forwarding behavior and backend TLS validation:

```yaml
security:
  forwardHostHeaders: true
  enableExploitProtection: false
  tls:
    insecureSkipVerify: false
    rootCAs: /etc/goma/certs/root.ca.pem
```

* **`forwardHostHeaders`** (`bool`, default: `true`): Whether to forward the original `Host` header.
* **`enableExploitProtection`** (`bool`, default: `false`): Enable built-in protections against known exploits.
* **`tls.insecureSkipVerify`** (`bool`, default: `false`): Disable TLS certificate verification for the backend. Forced to `true` when `gateway.networking.transport.insecureSkipVerify` is set.
* **`tls.rootCAs`**: Custom root CA (file path, raw PEM, or base64-encoded string).
* **`tls.clientCert`**, **`tls.clientKey`**: Client certificate and key presented to the backend (mTLS). They are only used when `tls.rootCAs` is also set. See [Mutual TLS (mTLS)](mtls.md).

---

## TLS Configuration

The route `tls` block selects how the certificate for the route's `hosts` is
obtained:

```yaml
tls:
  provider: letsencrypt        # a certManager provider name, or "none"
  certificate:                 # optional custom certificate for this route
    cert: /etc/goma/certs/api.crt
    key: /etc/goma/certs/api.key
```

* **`provider`** (`string`): Name of a provider under `certManager.providers`. Empty uses `certManager.defaultProvider`; `none` opts the route out of automatic certificates.
* **`certificate`** (`object`): A single `cert`/`key` pair (file path, raw PEM, or base64-encoded string) served for this route.

See [TLS & Let's Encrypt](tls.md#per-route-provider-selection).

---

## CORS

CORS is configured with the
[`responseHeaders` middleware](../middlewares/response-headers.md) and listed in
the route's `middlewares`:

```yaml
middlewares:
  - name: api-cors
    type: responseHeaders
    rule:
      cors:
        enabled: true
        origins:
          - http://localhost:3000
          - https://dev.example.com
        allowedHeaders:
          - Origin
          - Authorization
        maxAge: 86400
        allowCredentials: true

gateway:
  routes:
    - name: api
      path: /api
      target: http://api:8080
      middlewares: [api-cors]
```

:::warning[Removed in v1.0]

The per-route `cors` block was removed in v1.0. See
[Cross-Origin Resource Sharing](cors.md) for the replacement, and the
[v1.0 upgrade note](../upgrade/v1.0.md) for everything else that moved.

:::

---

## Route Priority

* Without `priority`, the most specific (longest) matching path wins.
* `priority` overrides that order among routes whose paths match the same
  request: lower numbers take precedence, and negative values are allowed. The
  default is `0`.


---

## Example: Route with Security

```yaml
version: 2
gateway:
  routes:
    - name: cart
      path: /cart
      rewrite: /
      target: http://cart-service:8080
      security:
        forwardHostHeaders: true
        enableExploitProtection: true
        tls:
          insecureSkipVerify: true
          rootCAs: /etc/goma/certs/root.ca.pem
```

---

## Example: Limited HTTP Methods

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      target: http://cart-service:8080
      methods: [POST, GET]
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

---

## Example: Route with Health Check

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      backends:
        - endpoint: http://cart-service:8080
      methods: [PATCH, GET]
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200, 404]
```

---

## Example: Route with Middleware

```yaml
version: 2
gateway:
  routes:
    - name: Example
      path: /store/cart
      rewrite: /
      backends:
        - endpoint: http://cart-service:8080
      healthCheck:
        path: "/health/live"
        interval: 30s
        timeout: 5s
        healthyStatuses: [200, 404]
      middlewares:
        - api-forbidden-paths
        - jwt-auth
```

---

## Example: Route with Load Balancing

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: example route
      hosts:
        - example.com
        - example.localhost
      rewrite: /
      backends:
        - endpoint: https://example.com
          weight: 1
        - endpoint: https://example1.com
          weight: 3
        - endpoint: https://example2.com
          weight: 2
      healthCheck:
        path: /
        interval: 30s
        timeout: 10s
        healthyStatuses: [200, 404]
```