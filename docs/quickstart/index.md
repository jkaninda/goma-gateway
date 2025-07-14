---
title: Quickstart
layout: home
nav_order: 3
---

# Quickstart Guide

## Prerequisites

Before you begin, ensure the following utilities are installed on your system:

* **Docker** — to run the Goma Gateway container
* **Kubernetes** (optional) — if you plan to deploy on Kubernetes

## Installation Steps

### Step 1: Generate the Default Configuration File

Use the following command to generate a default configuration file (`config.yml`):

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  jkaninda/goma-gateway config init --output /etc/goma/config.yml
```

This creates the configuration file under your local `./config` directory.

### Step 2: Customize the Configuration

Open and edit `./config/config.yml` to define your routes, middlewares, backends, and other settings as needed.

### Step 3: Validate Your Configuration

Before running the server, validate your configuration file for any errors:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  jkaninda/goma-gateway config check --config /etc/goma/config.yml
```

Fix any reported issues before proceeding.

### Step 4: Start the Goma Gateway Server

Run the server container, mounting your configuration and Let's Encrypt directories, and exposing the default ports:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  -v "${PWD}/letsencrypt:/etc/letsencrypt" \
  -p 8080:8080 \
  -p 8443:8443 \
  jkaninda/goma-gateway server --config /etc/goma/config.yml
```

By default, the gateway listens on:

* `8080` for HTTP traffic (`web` entry point)
* `8443` for HTTPS traffic (`webSecure` entry point)

---

## Optional: Configure EntryPoints to Use Ports 80 and 443

To run the gateway on standard HTTP/HTTPS ports (80 and 443), update your configuration as follows:

```yaml
version: 2
gateway:
  timeouts:
    write: 30
    read: 30
    idle: 30
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"
  extraConfig:
    # Additional gateway-specific configs here
```

Then start the container with the appropriate port bindings:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  -v "${PWD}/letsencrypt:/etc/letsencrypt" \
  -p 80:80 \
  -p 443:443 \
  jkaninda/goma-gateway server --config /etc/goma/config.yml
```

---

## Next Steps

Your Goma Gateway is now running and ready to route requests to your backend services.

* Customize your routes and middlewares further.
* Configure TLS certificates and security settings.
* Monitor traffic and logs to optimize performance.

Explore the full documentation for advanced features and configuration options.