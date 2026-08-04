---
title: Gateway
layout: default
parent: User Manual
nav_order: 1
---

# Gateway

The **Gateway** is the core entry point to your server. It manages inbound traffic, defines routing behavior, and controls security, monitoring, and performance settings.

This section describes how to configure the gateway to manage traffic effectively across your services.

---

## Configuration Overview

You can configure the gateway using the following options:

* **`redis`**: Redis-related configuration.
* **`tls`**: Global TLS settings for secure communication.
* **`timeouts`**: Server read/write/idle timeout settings.
* **`entryPoints`**: Network addresses and ports for incoming HTTP/HTTPS and TCP/UDP traffic.
* **`networking`**: Proxy networking options (e.g., connection pooling).
* **`monitoring`**: Metrics and health check configuration.
* **`defaults`**: Middlewares applied to every route, ahead of the route's own.
* **`reload`**: Token-protected on-demand configuration reload endpoint.
* **`enableStrictSlash`** (`boolean`): Whether the router should normalize paths with/without trailing slashes.

---

## TLS Configuration

Goma Gateway supports global TLS settings to secure incoming requests.

### Certificate Settings

TLS certificates can be configured using the following keys:

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

Configure timeouts (in seconds) for request handling:

* **`write`**: Timeout for writing responses.
* **`read`**: Timeout for reading requests.
* **`idle`**: Timeout for idle connections.

---

## CORS Configuration

Control Cross-Origin Resource Sharing behavior:

* **`origins`** (`[]string`): Allowed origins.
* **`headers`** (`map[string]string`): Custom response headers.
* **`allowedHeaders`** (`[]string`): Headers allowed in requests.
* **`exposeHeaders`** (`[]string`): Headers exposed to clients.
* **`maxAge`** (`int`): How long (in seconds) the preflight response is cached.
* **`allowMethods`** (`[]string`): Allowed HTTP methods.
* **`allowCredentials`** (`bool`): Whether credentials are allowed.

---

## Error Interceptor

Configure centralized error handling:

* **`enabled`** (`boolean`): Enable or disable the interceptor. *Default: `false`*
* **`contentType`** (`string`): Response content type (e.g., `application/json`).
* **`errors`** (`[]object`): Custom responses for specific HTTP status codes.

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

### PassThrough (TCP/UDP/gRPC Forwarding)

Configure TCP/UDP forwarding:

```yaml
passThrough:
  forwards:
    - protocol: tcp
      port: 2222
      target: srv1.example.com:62557
```

* **`protocol`**: One of `tcp`, `udp`, or `tcp/udp`.
* **`port`** (`int`): Listening port.
* **`target`** (`string`): Target address, e.g., `host:port`.

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


> 💡 **Note**: If `host` is not set, observability endpoints are accessible from any route host. To restrict access, set a specific `host` value.

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

This is stricter than a route referencing a missing middleware, which is only a
warning. The reason is blast radius: a typo in a route costs that one route its
middleware, while a typo in `defaults` silently leaves **every** route
unprotected by a policy the configuration appears to enforce.

A reload is never affected — if a reloaded configuration is invalid, the gateway
keeps serving the one it already has.

{: .warning }
> **Authentication in defaults affects every route, including ones that
> authenticate themselves.** A default `basicAuth`, `jwtAuth`, `oauth` or
> `forwardAuth` runs *before* a route's own auth middleware, so a route that
> already authenticates its callers will challenge them twice — or reject them
> outright, since the two schemes rarely accept the same credential. A Docker
> registry route is the common casualty: `docker login` fails against a gateway
> whose defaults add an unrelated auth middleware. Put authentication on the
> routes that need it, and keep defaults for policies that compose — rate limits,
> IP allowlists, access logging, response headers.

## Networking

The `networking` section defines low-level HTTP transport and connection pooling settings used by the internal proxy to forward traffic to backend services. These configurations help optimize performance, connection reuse, and resource usage across all routes.

### Transport Settings

These options apply to the internal HTTP client used by the gateway for outbound requests (HTTP or HTTPS). They are **global settings** and affect all routes.

---

###  Available Options

| Key                     | Type   | Default | Description                                                                              |
|-------------------------|--------|---------|------------------------------------------------------------------------------------------|
| `insecureSkipVerify`    | `bool` | `false` | Disables TLS certificate verification. Can be overridden per-route under `security.tls`. |
| `forceAttemptHTTP2`     | `bool` | `true`  | Enables HTTP/2 support when available from the upstream server.                          |
| `disableCompression`    | `bool` | `false` | Disables automatic gzip compression for proxied requests.                                |
| `maxIdleConns`          | `int`  | `1024`  | Maximum number of idle (keep-alive) connections allowed across all hosts.                |
| `maxIdleConnsPerHost`   | `int`  | `256`   | Maximum number of idle connections maintained per backend host.                          |
| `maxConnsPerHost`       | `int`  | `512`   | Maximum number of concurrent connections per host.                                       |
| `idleConnTimeout`       | `int`  | `90`    | Idle timeout (in seconds) before closing unused connections.                             |
| `tlsHandshakeTimeout`   | `int`  | `0`     | Timeout (in seconds) for completing the TLS handshake with a backend.                    |
| `responseHeaderTimeout` | `int`  | `0`     | Timeout (in seconds) to wait for the backend’s response headers.                         |

---

### Example Configuration

```yaml
gateway:
  networking:
    transport:
      insecureSkipVerify: true       # Optional, disables TLS verification, applies to all routes
      ## Optional, advanced configuration
      forceAttemptHTTP2: true
      disableCompression: false
      maxIdleConns: 512
      maxIdleConnsPerHost: 256
      maxConnsPerHost: 256
      idleConnTimeout: 90
      tlsHandshakeTimeout: 10
      responseHeaderTimeout: 10
```

---

## Extra Config

Load additional route and middleware configurations:

* **`directory`** (`string`): Directory containing config files.
* **`watch`** (`boolean`): Watch for changes and reload dynamically.

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

> 🔒 **Security**: Always set a strong `token` (ideally via `GOMA_RELOAD_TOKEN`). The endpoint is not registered unless both `enabled: true` and a token are present.

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

Define HTTP routing logic using the `routes` section. Each route specifies match criteria (e.g., path, host), backends, CORS, middlewares, and health checks.

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