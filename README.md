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
## Features Overview

**Goma Gateway** is a modern, developer-friendly API Gateway built for simplicity, security, and scale.
More than just a reverse proxy, it streamlines service infrastructure management with **declarative configuration** and **enterprise-grade features**.


## Core Capabilities

### **Routing & Traffic Management**

* Declarative **YAML-based configuration**
* Flexible routing for **domains, hosts, paths, WebSocket, gRPC, TCP/UDP**
* Multi-domain & multi-service support in one config
* Reverse proxy with backend abstraction
* Traffic control: **rate limiting, load balancing, health checks**
* **Canary Deployments**:
  Safely roll out new versions of your services with advanced canary deployment strategies:

  * **Weighted Backends** – Gradually shift traffic between service versions using percentage-based routing.
  * **Conditional Routing** – Route requests based on user groups, headers, query parameters, or cookies for targeted rollouts.

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

More than just a reverse proxy, Goma Gateway streamlines your services with declarative configuration and enterprise-grade features.

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

Handle REST APIs, WebSocket, gRPC, intelligent host & path routing.

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

Get started with **Goma Gateway** in just a few steps. This guide covers generating a configuration file, customizing it, validating your setup, and running the gateway with Docker.


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
          weight: 20
        - endpoint: https://api-2.example.com
          weight: 80
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
  goma-gateway:
    image: jkaninda/goma-gateway
    command: -c /etc/goma/config.yaml
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config:/etc/goma/
      - ./letsencrypt:/etc/letsencrypt

  api-example:
    image: jkaninda/okapi-example
```

Visit http://localhost/docs to see the documentation

### 7. Grafana Dashboard

Goma Gateway offers built-in monitoring capabilities to help you track the **health**, **performance**, and **behavior** of your gateway and its routes. Metrics are exposed in a **Prometheus-compatible** format and can be visualized using tools like **Prometheus** and **Grafana**.

A prebuilt **Grafana dashboard** is available to visualize metrics from Goma Gateway.

You can import it using dashboard ID: [23799](https://grafana.com/grafana/dashboards/23799)


#### Dashboard Preview

![Goma Gateway Grafana Dashboard](https://raw.githubusercontent.com/jkaninda/goma-gateway/main/docs/images/goma_gateway_observability_dashboard-23799.png)


### 8. Production Deployment Guide

For production deployments, use the example from the link below:

[production-deployment](https://github.com/jkaninda/goma-gateway-production-deployment).


### 9. Kubernetes deployment

#### Basic Deployment

```shell
kubectl apply -f https://raw.githubusercontent.com/jkaninda/goma-gateway/main/examples/k8s-basic-deployment.yaml
```

#### Advanced with CRDs

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

---

## License

This project is licensed under the Apache 2.0 License. See the LICENSE file for details.


## Copyright

Copyright (c) 2024–2025 Jonas Kaninda and contributors

<p align="center">
  <strong>Built with ❤️ for the developer community</strong>
</p>