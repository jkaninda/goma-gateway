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
    keys:
      - cert: /etc/goma/cert.pem
        key: /etc/goma/key.pem
      - cert: |
          -----BEGIN CERTIFICATE-----
          ...
        key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...  # Base64

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
    proxy:
      forceAttemptHTTP2: true
      disableCompression: false
      maxIdleConns: 1024
      maxIdleConnsPerHost: 256
      maxConnsPerHost: 512
      idleConnTimeout: 90
      tlsHandshakeTimeout: 10
      responseHeaderTimeout: 10

  errorInterceptor:
    enabled: true
    contentType: "application/json"
    errors:
      - status: 401
        body: ""
      - status: 500
        body: "Internal server error"

  cors:
    origins:
      - http://localhost:3000
      - https://dev.example.com
    allowedHeaders:
      - Origin
      - Authorization
      - X-Client-Id
      - Content-Type
      - Accept
    headers:
      X-Session-Id: xxx-xxx-xx
      Access-Control-Max-Age: 1728000
    exposeHeaders: []
    maxAge: 1728000
    allowMethods: ["GET", "POST"]
    allowCredentials: true

  extraConfig:
    directory: /etc/goma/extra
    watch: true

  routes: []
  middlewares: []
  certManager:
    acme:
      ## Uncomment email to enable Let's Encrypt
      #email: admin@example.com # Email for ACME registration
      storageFile: /etc/letsencrypt/acme.json
```