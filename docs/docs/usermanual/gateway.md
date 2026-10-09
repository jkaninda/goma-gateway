---
title: Gateway
sidebar_label: Gateway
sidebar_position: 1
---

# Gateway

The **Gateway** is the core entry point to your server. It manages inbound traffic, defines routing behavior, and controls security, monitoring, and performance settings.

This section describes how to configure the gateway to manage traffic effectively across your services.

---

## Configuration Overview

You can configure the gateway using the following options:

* **`entryPoints`**: Network addresses and ports for incoming HTTP/HTTPS and TCP/UDP traffic.
* **`tls`**: Global TLS certificates and client certificate authentication.
* **`timeouts`**: Server read/write/idle timeout settings.
* **`log`**: Log level, format and output file.
* **`monitoring`**: Metrics and health check configuration.
* **`proxy`**: Client IP resolution when running behind a reverse proxy or CDN.
* **`networking`**: Outbound transport options (connection pooling, DNS cache).
* **`redis`**: Redis connection, used for distributed rate limiting and caching.
* **`defaults`**: Middlewares applied to every route, ahead of the route's own.
* **`reload`**: Token-protected on-demand configuration reload endpoint.
* **`providers`**: Dynamic configuration sources (file, HTTP, Git). See [Providers](providers.md).
* **`extraConfig`**: Additional route and middleware files. See [Extra Config](extra-config.md).
* **`analytics`**: Per-request event stream published to Redis.
* **`geoip`**: Path to a MaxMind-format database used for country resolution.
* **`strictSlash`** (`boolean`, default: `true`): When enabled, the router matches a path with or without a trailing slash.
* **`debug`** (`boolean`, default: `false`): Enables debug mode. Also enabled when `log.level` is `debug` or `trace`.
* **`routes`**: The list of routes. See [Route](route.md).

---

## TLS Configuration

Goma Gateway supports global TLS settings to secure incoming requests.

| Key                   | Type       | Description                                                                                      |
|-----------------------|------------|--------------------------------------------------------------------------------------------------|
| `certificates`        | `[]object` | List of `cert`/`key` pairs served on the `webSecure` entry point.                                 |
| `certsDir`            | `string`   | Directory to load `<name>.crt`/`<name>.key` pairs from. Default: `/etc/goma/certs`.               |
| `default`             | `object`   | `cert`/`key` pair served when no other certificate matches. A self-signed one is generated if unset. |
| `clientAuth.clientCA` | `string`   | CA used to verify client certificates (mTLS).                                                     |
| `clientAuth.required` | `bool`     | Reject clients that do not present a valid certificate. Default: `false`.                        |

See [TLS & Let's Encrypt](tls.md) and [Mutual TLS (mTLS)](mtls.md) for details
and for automatic certificates with `certManager`.

### Certificate Settings

Each certificate entry uses the following keys:

* **`cert`** (`string`):
  The TLS certificate, provided as:

  * A file path,
  * Raw PEM-encoded content,
  * A base64-encoded string.

* **`key`** (`string`):
  The private key associated with the certificate, also accepted in:

  * File path,
  * Raw PEM format,
  * Base64-encoded string.

---

## Timeouts

Configure server timeouts (in seconds) under `gateway.timeouts`:

* **`write`**: Timeout for writing responses. Default: `60`.
* **`read`**: Timeout for reading requests. Default: `60`.
* **`idle`**: Timeout for idle keep-alive connections. Default: `60`.

A value of `0` disables the timeout. The `GOMA_TIMEOUT_WRITE`, `GOMA_TIMEOUT_READ`
and `GOMA_TIMEOUT_IDLE` environment variables override the configured values.
Request headers must always arrive within 10 seconds (`GOMA_TIMEOUT_READ_HEADER`).

```yaml
gateway:
  timeouts:
    write: 30
    read: 30
    idle: 60
```

---

## Logging

| Key          | Type     | Default  | Description                                                     |
|--------------|----------|----------|-----------------------------------------------------------------|
| `level`      | `string` | `error`  | Log level: `trace`, `debug`, `info`, `warn`, `error` or `off`. `goma config init` writes `info`. |
| `format`     | `string` | `text`   | Log format: `text` or `json`.                                   |
| `filePath`   | `string` | `""`     | Write logs to this file instead of stdout.                      |
| `maxAgeDays` | `int`    | —        | Maximum age of rotated log files, in days.                      |
| `maxBackups` | `int`    | —        | Maximum number of rotated log files to keep.                    |
| `maxSizeMB`  | `int`    | —        | Maximum size of a log file before it is rotated.                |

The `GOMA_LOG_LEVEL` environment variable overrides `level`.

---

:::warning[Removed in v1.0]

The gateway-level `cors` and `errorInterceptor` blocks were removed in v1.0.
Use the [`responseHeaders`](../middlewares/response-headers.md) and
[`errorInterceptor`](../middlewares/error-interceptor.md) middlewares instead,
applied through [`defaults`](#default-configuration) or per route. See the
[v1.0 upgrade notes](../upgrade/v1.0.md).

:::

---

## EntryPoints Configuration

Define how the gateway listens for traffic.

### Defaults

By default, the gateway listens on:

* `web`: Port `8080` (HTTP)
* `webSecure`: Port `8443` (HTTPS)

### HTTP/HTTPS Entry Points

* **`web.address`** (`string`): Network address/port for HTTP, e.g., `":80"` or `"0.0.0.0:8080"`.
* **`webSecure.address`** (`string`): Network address/port for HTTPS.

The `GOMA_ENTRYPOINT_WEB_ADDRESS` and `GOMA_ENTRYPOINT_WEB_SECURE_ADDRESS`
environment variables override these addresses.

### PassThrough (TCP/UDP/gRPC Forwarding)

Configure TCP/UDP forwarding:

```yaml
gateway:
  entryPoints:
    passThrough:
      forwards:
        - protocol: tcp
          port: 2222
          target: srv1.example.com:62557
```

* **`protocol`**: One of `tcp`, `udp`, or `tcp/udp`.
* **`port`** (`int`): Listening port.
* **`target`** (`string`): Target address, e.g., `host:port`.

See [TCP/UDP/gRPC Forwarding](tcp-udp-grpc.md) for details.

---

## Monitoring

The `monitoring` section allows you to configure observability endpoints for your gateway, including **Prometheus metrics**, **readiness/liveness probes**, and **route-level health checks**.

These features help you monitor system performance, readiness, and route-level health in production environments.

### Available Options

| Key                           | Type       | Default    | Description                                                           |
|-------------------------------|------------|------------|-----------------------------------------------------------------------|
| `host`                        | `string`   | `""`       | Restricts access to observability endpoints to a specific hostname.   |
| `enableMetrics`               | `bool`     | `false`    | Enables the Prometheus-compatible `/metrics` endpoint.                |
| `metricsPath`                 | `string`   | `/metrics` | Sets a custom path for metrics exposure.                              |
| `visitorTTL`                  | `string`   | `5m`       | How long a visitor keeps counting towards the real-time visitors gauge after their last request. |
| `enableReadiness`             | `bool`     | `true`     | Enables the `/readyz` readiness probe endpoint.                       |
| `enableLiveness`              | `bool`     | `true`     | Enables the `/healthz` liveness probe endpoint.                       |
| `enableRouteHealthCheck`      | `bool`     | `false`    | Enables the `/healthz/routes` endpoint for route-level health checks. |
| `includeRouteHealthErrors`    | `bool`     | `false`    | Includes route errors in the `/healthz/routes` response if `true`.    |
| `middleware.metrics`          | `[]string` | `[]`       | Middleware chain applied to the metrics endpoint.                     |
| `middleware.routeHealthCheck` | `[]string` | `[]`       | Middleware chain applied to the route health check endpoint.          |


:::note

If `host` is not set, observability endpoints are accessible from any route
host. Restrict them with `host`, or protect them with `middleware.metrics` and
`middleware.routeHealthCheck`; the gateway logs a warning at startup for each
endpoint that has neither.

:::

The `GOMA_ENABLE_METRICS`, `GOMA_ENABLE_READINESS` and `GOMA_ENABLE_LIVENESS`
environment variables override the corresponding settings.

---

### Example Configuration

```yaml
gateway:
  monitoring:
    host: ""            # Restrict observability access to this hostname
    enableMetrics: true                  # Enable Prometheus metrics
    metricsPath: /metrics                # Optional: customize metrics path
    enableReadiness: true               # Enable /readyz endpoint
    enableLiveness: true                # Enable /healthz endpoint
    enableRouteHealthCheck: true        # Enable /healthz/routes for route checks
    includeRouteHealthErrors: true      # Show failed routes in health response
    middleware:
      metrics:
        - ldap                          # Middleware for /metrics
      routeHealthCheck:
        - ldap                          # Middleware for /healthz/routes
```

---

## Proxy

Proxy settings help Goma correctly identify client IPs and handle requests when operating behind reverse proxies or CDNs.

### Available Options
| Key              | Type       | Default                           | Description                                                               |
|------------------|------------|-----------------------------------|---------------------------------------------------------------------------|
| `enabled`        | `bool`     | `false`                           | Set to `true` if Goma is behind a reverse proxy or CDN.                   |
| `trustedProxies` | `[]string` | `[]`                              | List of trusted proxy IPs or CIDRs to identify client IPs correctly.      |
| `ipHeaders`      | `[]string` | `["X-Forwarded-For","X-Real-IP"]` | List of headers to check (in order) for the client’s original IP address. |

`trustedProxies` must not be empty when `enabled` is `true`: forwarded headers
are only trusted from those sources. See
[Running behind a Proxy](running-behind-a-proxy.md).

---
### Example Configuration

```yaml
gateway:
  proxy:
    enabled: true                    # true if Goma is behind a proxy or CDN
    trustedProxies:                  # IPs or CIDRs for trusted proxy layers
      - "127.0.0.1"
      - "10.0.0.0/8"
      - "192.168.0.0/16"
    ipHeaders:                       # List of headers to check, in order
      - "CF-Connecting-IP"
      - "X-Forwarded-For"
      - "X-Real-IP"
      - "True-Client-IP"
      - "Forwarded"
```
---


## Default Configuration

The **default configuration** defines global settings that are automatically applied to all routes in the gateway.

In particular, the `middlewares` field under `defaults` allows you to specify middleware that should be executed for every route by default. 
This is useful for applying common security, authentication, or rate-limiting policies across your entire gateway.

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"

  # Default middlewares automatically applied to all routes
  defaults:
    middlewares:
      - rate-limit
      - basic-auth
```

### Execution order

Default middlewares run **before** a route's own, in the order listed:

```
defaults.middlewares…  →  route.middlewares…  →  backend
```

That ordering is what makes a default useful for a policy that must not be
bypassable — a rate limit or an IP allowlist runs before anything a route
declares for itself.

### Overriding the order for one route

A route that lists a default by name keeps **its own** position for it, and the
default is not prepended a second time. Use this when a route needs a default to
run later in its chain:

```yaml
defaults:
  middlewares: [rate-limit, basic-auth]

routes:
  - name: api
    middlewares: [cors]                    # → rate-limit, basic-auth, cors
  - name: upload
    middlewares: [cors, rate-limit]        # → basic-auth, cors, rate-limit
```

There is no way to *remove* a default from a single route. If a policy should not
apply everywhere, declare it on the routes that need it instead.

### Every default must be defined

A name in `defaults.middlewares` that matches no middleware definition is a
**fatal configuration error** — the gateway logs it and refuses to start:

```
defaults.middlewares references an undefined middleware "basic-auht";
it would be applied to every route and silently do nothing
```

This is stricter than a route referencing a missing middleware, which is logged
as an error while that one route rejects every request with `503`. The reason is
blast radius: a typo in `defaults` would take **every** route down.

A reload is never affected — if a reloaded configuration is invalid, the gateway
keeps serving the one it already has.

:::warning

**Authentication in defaults affects every route, including ones that
authenticate themselves.** A default `basicAuth`, `jwtAuth`, `oauth` or
`forwardAuth` runs *before* a route's own auth middleware, so a route that
already authenticates its callers will challenge them twice — or reject them
outright, since the two schemes rarely accept the same credential. A Docker
registry route is the common casualty: `docker login` fails against a gateway
whose defaults add an unrelated auth middleware. Put authentication on the
routes that need it, and keep defaults for policies that compose — rate limits,
IP allowlists, access logging, response headers.

:::

## Networking

The `networking` section defines low-level HTTP transport and connection pooling settings used by the internal proxy to forward traffic to backend services. These configurations help optimize performance, connection reuse, and resource usage across all routes.

### Transport Settings

These options apply to the internal HTTP client used by the gateway for outbound requests (HTTP or HTTPS). They are **global settings** and affect all routes.

---

###  Available Options

| Key                     | Type   | Default | Description                                                                              |
|-------------------------|--------|---------|------------------------------------------------------------------------------------------|
| `insecureSkipVerify`    | `bool` | `false` | Disables backend TLS certificate verification for **every** route; when `true`, a route cannot turn verification back on. |
| `forceAttemptHTTP2`     | `bool` | `true`  | Enables HTTP/2 support when available from the upstream server.                          |
| `disableCompression`    | `bool` | `false` | Disables automatic gzip compression for proxied requests.                                |
| `maxIdleConns`          | `int`  | `512`   | Maximum number of idle (keep-alive) connections allowed across all hosts.                |
| `maxIdleConnsPerHost`   | `int`  | `256`   | Maximum number of idle connections maintained per backend host.                          |
| `maxConnsPerHost`       | `int`  | `256`   | Maximum number of concurrent connections per host.                                       |
| `idleConnTimeout`       | `int`  | `90`    | Idle timeout (in seconds) before closing unused connections.                             |
| `tlsHandshakeTimeout`   | `int`  | `0`     | Timeout (in seconds) for completing the TLS handshake with a backend. `0` means no timeout. |
| `responseHeaderTimeout` | `int`  | `0`     | Timeout (in seconds) to wait for the backend’s response headers. `0` means no timeout.     |

### DNS Cache

Backend host names are resolved through a shared DNS cache, configured under
`networking.dnsCache`:

| Key             | Type       | Default | Description                                                          |
|-----------------|------------|---------|----------------------------------------------------------------------|
| `ttl`           | `int`      | `300`   | Cache entry lifetime, in seconds.                                    |
| `clearOnReload` | `bool`     | `false` | Flush the cache when routes are reloaded.                            |
| `resolver`      | `[]string` | `[]`    | Custom DNS servers (e.g. `1.1.1.1`, `8.8.8.8:53`). Empty uses the system resolver. |

### Passive Health Check

On a route with several `backends`, a backend that fails `maxFails` requests in a
row at the connection level (connection refused or reset, timeout) is taken out
of rotation for `ejectFor`, with no `healthCheck` block needed. Configured under
`networking.passiveHealthCheck`:

| Key        | Type     | Default | Description                                                        |
|------------|----------|---------|--------------------------------------------------------------------|
| `enabled`  | `bool`   | `true`  | Turn passive health checks on or off.                              |
| `maxFails` | `int`    | `2`     | Consecutive connection failures that eject a backend.              |
| `ejectFor` | `string` | `10s`   | How long an ejected backend stays out of rotation, as a Go duration. |

See [Load Balancing](../monitoring-and-performance/load-balancing.md#passive-health-checks) for how ejection works.

---

### Example Configuration

```yaml
gateway:
  networking:
    transport:
      insecureSkipVerify: false      # true disables backend TLS verification for all routes
      ## Optional, advanced configuration
      forceAttemptHTTP2: true
      disableCompression: false
      maxIdleConns: 512
      maxIdleConnsPerHost: 256
      maxConnsPerHost: 256
      idleConnTimeout: 90
      tlsHandshakeTimeout: 10
      responseHeaderTimeout: 10
    passiveHealthCheck:
      enabled: true
      maxFails: 2
      ejectFor: 10s
```

---

## Extra Config

Load additional route and middleware configurations from a directory:

* **`directory`** (`string`): Directory containing config files. Overridden by `GOMA_EXTRA_CONFIG_DIR`.
* **`watch`** (`boolean`): Watch for changes and reload dynamically. Overridden by `GOMA_EXTRA_CONFIG_WATCH`.

See [Extra Config](extra-config.md).

---

## On-Demand Reload

The `reload` section exposes a token-protected endpoint that lets an external controller tell the gateway to pull its configuration from the active providers and apply it **immediately**, instead of waiting for the provider poll interval.

### Available Options

| Key       | Type     | Default           | Description                                                                                             |
|-----------|----------|-------------------|---------------------------------------------------------------------------------------------------------|
| `enabled` | `bool`   | `false`           | Exposes the reload endpoint. Only registered when `enabled` is `true` **and** a token is set.           |
| `path`    | `string` | `/gateway/reload` | Path of the reload endpoint.                                                                             |
| `token`   | `string` | `""`              | Bearer token required in the `Authorization: Bearer <token>` header. Prefer the `GOMA_RELOAD_TOKEN` env var over storing it in the config file. |
| `host`    | `string` | `""`              | Restrict the endpoint to requests with this `Host` header. Empty allows any host.                       |

### Endpoint Behavior

Send `POST <path>` with the `Authorization: Bearer <token>` header:

| Status | Meaning                                                                                     |
|--------|---------------------------------------------------------------------------------------------|
| `200`  | Reload succeeded. Body: `{status, routes, durationMs}`.                                      |
| `401`  | Missing or invalid token.                                                                   |
| `500`  | Reload failed — the gateway keeps serving its current configuration.                        |

:::warning[Security]

Always set a strong `token`, ideally via `GOMA_RELOAD_TOKEN`. The endpoint is
not registered unless both `enabled: true` and a token are present.

:::

### Example Configuration

```yaml
gateway:
  reload:
    enabled: true
    path: /gateway/reload          # Optional, defaults to /gateway/reload
    token: ""                      # Prefer setting GOMA_RELOAD_TOKEN instead
    host: ""                       # Optional, restrict to a specific Host header
```

Trigger a reload:

```bash
curl -X POST https://gateway.example.com/gateway/reload \
  -H "Authorization: Bearer $GOMA_RELOAD_TOKEN"
```

---

## Routes

Define HTTP routing logic using the `routes` section. Each route specifies match criteria (e.g., path, host), backends, middlewares, and health checks. See [Route](route.md).

---

## Minimal Configuration

```yaml
version: 2
gateway:
  routes: []
```

---

## Example: Custom EntryPoints

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"
```

---

## Full Example Configuration

```yaml
version: 2
gateway:
  timeouts:
    write: 30
    read: 30
    idle: 30

  tls:
    certificates:
      - cert: /etc/goma/cert.pem
        key: /etc/goma/key.pem
      - cert: |
          -----BEGIN CERTIFICATE-----
          ...
        key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...  # Base64
    # Default cert
    default:
      cert: /etc/goma/default-cert.pem
      key: /etc/goma/default-key.pem
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"
    passThrough:
      forwards:
        - protocol: tcp
          port: 2222
          target: srv1.example.com:62557
        - protocol: tcp/udp
          port: 53
          target: 10.25.10.15:53
        - protocol: tcp
          port: 5050
          target: 10.25.10.181:4040
        - protocol: udp
          port: 55
          target: 10.25.10.20:53

  log:
    level: info
    filePath: ''
    format: json

  monitoring:
    enableMetrics: true             
    metricsPath: /metrics           
    enableReadiness: true           
    enableLiveness: true            
    enableRouteHealthCheck: true    
    includeRouteHealthErrors: true  
    middleware:
      metrics:
        - ldap                      
      routeHealthCheck:
        - ldap                      

  networking:
    transport:
      forceAttemptHTTP2: true
      disableCompression: false
      maxIdleConns: 1024
      maxIdleConnsPerHost: 256
      maxConnsPerHost: 512
      idleConnTimeout: 90
      tlsHandshakeTimeout: 10
      responseHeaderTimeout: 10
    dnsCache:
      ttl: 300
      clearOnReload: true
      # resolver: ["1.1.1.1", "8.8.8.8:53"]   # empty = the system resolver

  # Real client IP when Goma runs behind another proxy or a CDN. Only enable it
  # when that is true: a forwarded header is trusted from trustedProxies sources,
  # so enabling it while directly exposed lets any client spoof its IP.
  proxy:
    enabled: false
    trustedProxies:
      - "10.0.0.0/8"
      - "fc00::/7"
    ipHeaders:
      - "CF-Connecting-IP"
      - "X-Forwarded-For"

  # Shared cache and distributed rate limiting. Without it those middlewares fall
  # back to per-instance memory.
  redis:
    addr: redis:6379
    password: ""

  # Emit one event per request to a Redis stream for an external consumer.
  analytics:
    enabled: false
    stream: goma:analytics
    sample: 1
    maxLen: 1000000

  # Country resolution for analytics and the geoBlock middleware. Goma ships no
  # database; drop a MaxMind-format .mmdb at this path to enable it.
  geoip:
    database: /etc/goma/country.mmdb

  # Middlewares applied to every route, ahead of the route's own.
  defaults:
    middlewares: []

  # Token-protected endpoint that makes the gateway pull its configuration now
  # instead of waiting for the provider poll.
  reload:
    enabled: false
    path: /gateway/reload
    # Prefer GOMA_RELOAD_TOKEN over writing the token here.
    host: ""

  # Dynamic configuration sources, merged with the routes below.
  providers:
    file:
      enabled: true
      directory: /etc/goma/providers
      watch: true

  extraConfig:
    directory: /etc/goma/extra
    watch: true

  strictSlash: true
  debug: false

  routes: []

middlewares: []

# Named certificate providers, selected per route with `tls.provider: <name>`
# (or `none` to opt out). defaultProvider serves routes that name none.
certManager:
  defaultProvider: acme
  providers:
    acme:
      type: acme
      acme:
        email: admin@example.com
        storageFile: /etc/letsencrypt/acme.json
        # directoryUrl: https://acme-staging-v02.api.letsencrypt.org/directory
```