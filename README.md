# Goma Gateway — Lightweight API Gateway and Reverse Proxy with declarative config, robust middleware.

```
   ____                       
  / ___| ___  _ __ ___   __ _ 
 | |  _ / _ \| '_ ` _ \ / _` |
 | |_| | (_) | | | | | | (_| |
  \____|\___/|_| |_| |_|\__,_|
  :: Goma Gateway :: - ()
                               
```
---

[![Tests](https://github.com/jkaninda/goma-gateway/actions/workflows/test.yml/badge.svg)](https://github.com/jkaninda/goma-gateway/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jkaninda/goma-gateway)](https://goreportcard.com/report/github.com/jkaninda/goma-gateway)
[![Go](https://img.shields.io/github/go-mod/go-version/jkaninda/goma-gateway)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/jkaninda/goma-gateway.svg)](https://pkg.go.dev/github.com/jkaninda/goma-gateway)
[![GitHub Release](https://img.shields.io/github/v/release/jkaninda/goma-gateway)](https://github.com/jkaninda/goma-gateway/releases)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jkaninda/goma-gateway?style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/jkaninda/goma-gateway?style=flat-square)

**Goma Gateway** is a high-performance, security-focused API Gateway built for modern developers and cloud-native environments. With a powerful feature set, intuitive configuration, and first-class support for observability, Goma helps you route, secure, and scale traffic effortlessly.


The project is named after Goma, a vibrant city located in the eastern region of the Democratic Republic of the Congo — known for its resilience, beauty, and energy.


<p align="center">
  <img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/logo.png" width="150" alt="Okapi logo">
</p>


Architecture:

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/goma-gateway.png" width="912" alt="Goma architecture">


## Links:

- [Docker Hub](https://hub.docker.com/r/jkaninda/goma-gateway)
- [Github](https://github.com/jkaninda/goma-gateway)
- [Kubernetes operator](https://github.com/jkaninda/goma-operator)

### [Documentation](https://jkaninda.github.io/goma-gateway)

---
## Features

**Goma Gateway** is a modern, developer-friendly API Gateway built for simplicity, security, and scale.
More than just a reverse proxy, it streamlines service infrastructure management with **declarative configuration** and **enterprise-grade features**.


## Core Capabilities

### **Routing & Traffic Management**

* Declarative **YAML-based configuration**
* Flexible routing for **domains, hosts, paths, WebSocket, gRPC, TCP/UDP**
* Multi-domain & multi-service support in one config
* Reverse proxy with backend abstraction
* Traffic control: **rate limiting, load balancing, health checks**

### **Security & Access Control**

* Automatic HTTPS via **Let’s Encrypt** or custom TLS
* **Mutual TLS (mTLS)** for client certificate authentication
* Built-in authentication: **Basic Auth, JWT, OAuth, LDAP, ForwardAuth**
* CORS policies, header injection, fine-grained access control
* Exploit protection: **SQL injection, XSS**, and bot detection
* Method restrictions and regex-based URL rewriting

### **Performance & Reliability**

* **HTTP caching** (in-memory or Redis) with smart invalidation
* Load balancing: round-robin, weighted, with health checks
* Scalable rate limiting: local or Redis-based
  *(with automatic banning for repeated abuse)*

### **Operations & Monitoring**

* Zero-downtime config reloads
* Structured logging with configurable levels
* Prometheus/Grafana metrics
* Graceful error handling and backend failure interception

### **Cloud-Native Integration**

* Kubernetes CRD support for native resource management
* GitOps-friendly with version-controlled configs
* Modular config files for organized route management
* Horizontal scalability & dynamic backend updates

---

## Why Goma Gateway?

### **1. Simple, Declarative Configuration**

Write clear YAML for routes, middleware, policies, and TLS.
Supports single-file or multi-file setups, intuitive and maintainable.

### **2. Security First**

* Auto HTTPS & mTLS
* Multiple authentication methods
* Built-in exploit prevention
* Fine-grained access control
* Scalable rate limiting with abuse detection

### **3. Multi-Domain & Smart Routing**

Handle REST APIs, WebSocket, gRPC, or static content with intelligent host & path routing.

### **4. Live Reload & GitOps Ready**

Apply changes instantly without restarts — perfect for CI/CD pipelines.

### **5. Full Observability**

* Structured logging
* Prometheus metrics
* Grafana dashboards

### **6. Built for Speed**

* Intelligent HTTP caching
* Advanced load balancing
* Health-aware backend routing


**Perfect for:** Public APIs, internal microservices, legacy modernization, or any project requiring secure, scalable traffic management.


---
## Quickstart Guide

### Prerequisites

Before you begin, ensure the following utilities are installed on your system:

* **Docker** — to run the Goma Gateway container
* **Kubernetes** (optional) — if you plan to deploy on Kubernetes

### Installation Steps

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

Run the server container, mounting your configuration, and Let's Encrypt directories, and exposing the default ports:

```bash
docker run --rm --name goma-gateway \
  -v "${PWD}/config:/etc/goma/" \
  -v "${PWD}/letsencrypt:/etc/letsencrypt" \
  -p 8080:8080 \
  -p 8443:8443 \
  jkaninda/goma-gateway --config /etc/goma/config.yml
```

By default, the gateway listens on:

* `8080` for HTTP traffic (`web` entry point)
* `8443` for HTTPS traffic (`webSecure` entry point)

---

### Optional: Use Standard Ports (`80` & `443`)

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
  jkaninda/goma-gateway --config /etc/goma/config.yml
```
### 5. Health Checks

Goma Gateway provides the following health check endpoints:
- Gateway Health:
  - `/readyz`
  - `/healthz`
- Routes Health: `/healthz/routes`

### 6. Simple Deployment with Docker Compose

Here’s a simple example of deploying Goma Gateway using Docker Compose:

Create a file named `config.yaml`:

```yaml
version: 2
gateway:
  # Timeout settings (in seconds)
  timeouts:
    write: 30
    read: 30
    idle: 30
  # Optional, default port 8080
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"
  extraConfig:
    directory: /etc/goma/extra
    watch: true
  # Route definitions
  routes:
    #  Route definition 1
    - path: /                # Base path to match
      enabled: false         # Whether the route is enabled
      name: minimal           # Descriptive name for the route
      hosts:                  # Host-based routing (virtual hosting)
        - minimal.example.com    # Only match requests for this host
      target: https://example.com  # Target URL for this route
    #  Route definition 2
    - path: /                # Base path to match
      name: example           # Descriptive name for the route
      rewrite: ''             # Path rewrite rule (empty means no rewrite)
      target: https://example.com  # Target URL for this route
      cors: {}                # CORS settings
      security:
        forwardHostHeaders: false
        enableExploitProtection: true
        tls:
          insecureSkipVerify: true
          rootCAs: ""
      middlewares:
      - basic-auth          # Apply basic authentication middleware
    #  Route definition 3
    - name: api
      path: /
      hosts:                  # Host-based routing (virtual hosting)
        - api.example.com    # Only match requests for this host
      rewrite: /
      backends:               # Load balancing backends
        - endpoint: https://api-1.example.com
          weight: 1
        - endpoint: https://api-2.example.com
          weight: 3
      healthCheck:
        path: /
        interval: 30s
        timeout: 10s
        healthyStatuses:
          - 200
          - 404
      middlewares: []         # No middlewares for this route

# Middleware definitions
middlewares:
  - name: basic-auth          # Middleware identifier
    type: basicAuth               # Middleware type (basic auth)
    paths:
      - /admin                   # Apply to /admin and all subpaths
    rule:
      realm: Restricted
      forwardUsername: true  # Forward authenticated username to backend
      users:
        - username: admin
          password: $2y$05$TIx7l8sJWvMFXw4n0GbkQuOhemPQOormacQC4W1p28TOVzJtx.XpO # bcrypt hash for 'admin', password: admin
        - username: user
          password: password # Plaintext password for 'user'
# Certificate management configuration
certManager:
  acme:
    ## Uncomment email to enable Let's Encrypt
    # email: admin@example.com # Email for ACME registration
    storageFile: /etc/letsencrypt/acme.json
```

```shell
# compose.yaml
services:
  goma-gateway:
    image: jkaninda/goma-gateway
    command: server -c config.yaml
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./:/etc/goma/
      - ./letsencrypt:/etc/letsencrypt
```

### 7. Grafana Dashboard

Goma Gateway offers built-in monitoring capabilities to help you track the **health**, **performance**, and **behavior** of your gateway and its routes. Metrics are exposed in a **Prometheus-compatible** format and can be visualized using tools like **Prometheus** and **Grafana**.

A prebuilt **Grafana dashboard** is available to visualize metrics from Goma Gateway.

You can import it using dashboard ID: [23799](https://grafana.com/grafana/dashboards/23799)


#### Dashboard Preview

![Goma Gateway Grafana Dashboard](https://raw.githubusercontent.com/jkaninda/goma-gateway/main/docs/images/goma_gateway_observability_dashboard-23799.png)


### 8. Kubernetes deployment

-  [Kubernetes installation](https://jkaninda.github.io/goma-gateway/install/kubernetes.html)

- [Kubernetes advanced deployment using CRDs and Operator](https://jkaninda.github.io/goma-gateway/install/kuberntes-advanced.html)

## Supported Systems

- [x] Linux
- [x] MacOS
- [x] Windows

Please download the binary from the [release page](https://github.com/jkaninda/goma-gateway/releases).

Init configs:

```shell
./goma config init --output config.yml
```

To run
```shell
./goma server --config config.yml
```
---
## Deployment

- Docker
- Kubernetes

## Contributing

The Goma Gateway project welcomes all contributors. We appreciate your help!

## 🌟 Star History

⭐ If you find Goma Gateway useful, please consider giving it a star on [GitHub](https://github.com/jkaninda/goma-gateway)!

[![Star History Chart](https://api.star-history.com/svg?repos=jkaninda/goma-gateway&type=Date)](https://star-history.com/#jkaninda/goma-gateway&Date)


## Give a Star! ⭐

If this project helped you, do not skip on giving it a star. Thanks!

## Performance Benchmark: Traefik vs Goma Gateway

This benchmark compares **Traefik** and **Goma Gateway** under identical load conditions using [`wrk`](https://github.com/wg/wrk), a modern HTTP benchmarking tool.


> **Test environment:** 8 threads, 500 concurrent connections, 60 seconds duration

---

## Summary

| **Metric**              | **Traefik**  | **Goma Gateway** |
|-------------------------|--------------|------------------|
| **Requests/sec**        | 🟢 29,278.35 | 23,108.16        |
| **Avg Latency**         | 81.58 ms     | 🟢 **71.92 ms**  |
| **Latency StdDev**      | 143.85 ms    | 🟢 **120.47 ms** |
| **Max Latency**         | 🟢 1.54 s    | 1.82 s           |
| **Total Requests**      | 🟢 1,757,995 | 1,388,634        |
| **Timeouts**            | 74           | 🟢 **18**        |
| **Transfer/sec**        | 6.42 MB      | 🟢 **6.81 MB**   |
| **Memory (Idle)**       | \~76 MB      | 🟢 **\~5 MB**    |
| **Memory (Under Load)** | \~250 MB     | 🟢 **\~50 MB**   |

## Reproducing the Test

If you want to reproduce this benchmark, you can use the repository below:

Repository: [jkaninda/goma-gateway-vs-traefik](https://github.com/jkaninda/goma-gateway-vs-traefik)



---

## License

This project is licensed under the Apache 2.0 License. See the LICENSE file for details.


## Copyright

Copyright (c) 2024–2025 Jonas Kaninda and contributors