---
title: Quickstart
layout: home
nav_order: 3
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

This will generate the configuration under `./config/config.yml`.


### 2. Customize the Configuration

Edit `./config/config.yml` to define your **routes**, **middlewares**, **backends**, and other settings.



### 3. Validate Your Configuration

Check the configuration for errors before starting the server:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  jkaninda/goma-gateway config check --config /etc/goma/config.yml
```

Fix any reported issues before proceeding.

---

### 4. Start the Gateway

Launch the server with your configuration and Let's Encrypt volumes:

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


### 6. Health Checks

Goma Gateway exposes the following endpoints:

* Gateway health:

    * `/readyz`
    * `/healthz`
* Routes health:

    * `/healthz/routes`


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
        - username: admin
          password: $2y$05$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO # bcrypt hash for 'admin'
        - username: user
          password: password
certManager:
  acme:
    ## Uncomment email to enable Let's Encrypt
    # email: admin@example.com # Email for ACME registration
    storageFile: /etc/letsencrypt/acme.json
```

**`compose.yaml`**

```yaml
services:
  gateway:
    image: jkaninda/goma-gateway
    command: -c /etc/goma/config.yaml
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./:/etc/goma/
      - ./letsencrypt:/etc/letsencrypt

  api-example:
    image: jkaninda/okapi-example
```

Visit http://localhost/docs to see the documentation


---

## Next Steps

Your Goma Gateway is up and running. From here, you can:

* Define advanced routes and middlewares
* Configure TLS certificates and security policies
* Monitor traffic and logs to optimize performance

Explore the [full documentation](#) for advanced features and best practices.
