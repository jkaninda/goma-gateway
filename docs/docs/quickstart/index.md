---
title: Quickstart
sidebar_label: Quickstart
sidebar_position: 3
---

# Quickstart Guide

Get started with **Goma Gateway** in just a few steps. This guide covers generating a configuration file, customizing it, validating your setup, and running the gateway with Docker.

---

## Prerequisites

Before you begin, ensure you have:

* **Docker** — to run the Goma Gateway container
* **Kubernetes** *(optional)* — if you plan to deploy on Kubernetes


## Installation Steps

### 1. Generate a Default Configuration

Run the following command to create a default configuration file (`config.yml`):

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  jkaninda/goma-gateway config init --output /etc/goma/config.yml
```

This generates `./config/config.yml`. The generated configuration includes a
`basic-auth` middleware whose `admin` password is created at random and printed
**once** in the command output; change or remove it before exposing the gateway.


### 2. Customize the Configuration

Edit `./config/config.yml` to define your **routes**, **middlewares**, **backends**, and other settings.
See [Gateway](../usermanual/gateway.md) and [Route](../usermanual/route.md) for the available options.


### 3. Validate Your Configuration

Check the configuration for errors before starting the server:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  jkaninda/goma-gateway config check --config /etc/goma/config.yml
```

The check lists every problem it finds (unknown or misspelled keys, invalid
middleware rules, routes without a target or referencing an undefined middleware)
and exits with a non-zero status if there is any. Fix them before proceeding.

---

### 4. Start the Gateway

Launch the server with your configuration and a volume for certificates
issued through Let's Encrypt:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  -v "${PWD}/letsencrypt:/etc/letsencrypt" \
  -p 8080:8080 \
  -p 8443:8443 \
  jkaninda/goma-gateway --config /etc/goma/config.yml
```

By default, Goma Gateway listens on:

* **8080** → HTTP (`web` entry point)
* **8443** → HTTPS (`webSecure` entry point)

Without a `--config` flag, the gateway reads `/etc/goma/goma.yml` (or the path in
the `GOMA_CONFIG_FILE` environment variable), and generates a default
configuration there if the file does not exist.

---

### 5. (Optional) Use Standard Ports 80 & 443

To run on standard HTTP/HTTPS ports, update your config:

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"
```

Start the container with:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  -v "${PWD}/letsencrypt:/etc/letsencrypt" \
  -p 80:80 \
  -p 443:443 \
  jkaninda/goma-gateway --config /etc/goma/config.yml
```

The container runs as root by default, which is what lets it bind 80 and 443
directly. To run unprivileged instead, see
[Running as a Non-Root User](../install/docker.md#6-running-as-a-non-root-user).


### 6. Health Checks

Goma Gateway exposes the following endpoints:

* Gateway health (enabled by default):

    * `/readyz`
    * `/healthz`
* Routes health (only when `gateway.monitoring.enableRouteHealthCheck: true`):

    * `/healthz/routes`

See [Health check](../usermanual/healthcheck.md) for details.


### 7. Deploy with Docker Compose

A simple `docker-compose` setup:

**`config.yaml`**

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"
  log:
    level: info
  routes:
    - name: api-example
      path: /
      target: http://api-example:8080
      middlewares: ["rate-limit","basic-auth"]
    - name: host-example
      path: /api
      rewrite: /
      hosts:
        - api.example.com
      backends:
        - endpoint: https://api-1.example.com
          weight: 1
        - endpoint: https://api-2.example.com
          weight: 3
      healthCheck:
        path: /
        interval: 30s
        timeout: 10s
middlewares:
  - name: rate-limit
    type: rateLimit
    rule:
      unit: minute
      requestsPerUnit: 20
      banAfter: 5
      banDuration: 5m
  - name: basic-auth
    type: basicAuth
    paths: ["/admin","/docs","/openapi"]
    rule:
      realm: Restricted
      forwardUsername: true
      users:
        # Generate your own hash — never copy one out of documentation:
        #   htpasswd -nbBC 12 admin 'your-password' | cut -d: -f2
        # or keep it out of the file entirely with ${VAR} expansion.
        - username: admin
          password: ${GOMA_ADMIN_PASSWORD_HASH}
## Uncomment to issue Let's Encrypt certificates for route hosts
# certManager:
#   providers:
#     letsencrypt:
#       type: acme
#       acme:
#         email: admin@example.com # Email for ACME registration
```

**`compose.yaml`**

```yaml
services:
  gateway:
    image: jkaninda/goma-gateway
    command: -c /etc/goma/config.yaml
    environment:
      # bcrypt hash for the basic-auth user, passed through from your shell
      - GOMA_ADMIN_PASSWORD_HASH
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./:/etc/goma/
      - ./letsencrypt:/etc/letsencrypt

  api-example:
    image: jkaninda/okapi-example
```

Export `GOMA_ADMIN_PASSWORD_HASH` in your shell before running
`docker compose up`, then visit http://localhost/docs to see the example API
documentation (protected by the `basic-auth` middleware).


---

## Next Steps

Your Goma Gateway is up and running. From here, you can:

* Define advanced [routes](../usermanual/route.md) and [middlewares](../middlewares/overview.md)
* Configure [TLS certificates](../usermanual/tls.md) and security policies
* [Monitor](../monitoring-and-performance/monitoring.md) traffic and logs to optimize performance
