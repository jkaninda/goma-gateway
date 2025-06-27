# Goma Gateway - simple Lightweight High-Performance Declarative API Gateway Management.

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

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/goma-gateway.png" width="912" alt="Goma archi">


## Links:

- [Docker Hub](https://hub.docker.com/r/jkaninda/goma-gateway)
- [Github](https://github.com/jkaninda/goma-gateway)
- [Kubernetes operator](https://github.com/jkaninda/goma-operator)

### [Documentation](https://jkaninda.github.io/goma-gateway)

---
## Features

Goma Gateway is designed for simplicity, flexibility, and robust performance. It supports a wide range of modern features, empowering you to manage and secure traffic efficiently across services.


### Core Features

* **RESTful API Gateway Management**
  Intuitively manage APIs with a clean, declarative configuration system.

* **Domain & Host-Based Routing**
  Route requests by domain or host to different services or environments.

* **Multi-Domain Support**
  Handle traffic across multiple domains with unified configuration.

* **Reverse Proxy Support**
  Forward incoming client requests to backend services seamlessly.

* **WebSocket Proxying**
  Enable real-time applications with full WebSocket support.

---

### Security & Access Control

* **TLS with Automatic Certificate Management**
  Secure your services with built-in TLS support, including:

  * **Free, Auto-Generated Certificates** via Let's Encrypt.
  * **Automatic Renewal & Storage** to ensure uninterrupted HTTPS.
  * **Custom TLS Certificates Support**
  
  Bring your own TLS certificates when needed:
  * Fallback to auto-generation when no custom cert is provided.

* **Cross-Origin Resource Sharing (CORS)**
  Define and enforce CORS policies per route for controlled cross-origin access.

* **Custom Header Injection**
  Add or override HTTP headers for fine-grained request/response control.

* **Authentication Middleware**

  * **ForwardAuth** support for external authorization services.
  * Built-in support for **Basic Auth**, **JWT**, and **OAuth**.

* **Access Policy Enforcement**
  Allow or deny traffic based on route-specific rules (IP, headers, methods, etc.).

* **Exploit Protection Middleware**
  Block common attack patterns like:

  * SQL injection attempts.
  * Cross-site scripting (XSS).

* **Regex URL Rewriting**
  Modify request paths on the fly using powerful regex rules.

* **Bot Detection**
  Identify and block traffic from known bots using user-agent analysis.

* **HTTP Method Restrictions**
  Explicitly restrict which HTTP methods are allowed per route.

### Monitoring & Observability

* **Comprehensive Logging**
  Capture full request/response details with support for log levels (INFO, DEBUG, ERROR).

* **Metrics Collection**
  Track key metrics like response times, error rates, and throughput.
  Integrates with **Prometheus**, **Grafana**, and other observability platforms.

### Rate Limiting & Throttling

* **In-Memory Rate Limiting**
  IP-based throttling suitable for single-instance deployments.

* **Distributed Rate Limiting with Redis**
  Scalable enforcement of request limits across multiple gateway instances.

* **Customizable Policies**
  Configure thresholds (e.g., X requests per Y seconds) to protect APIs.


###  Load Balancing

* **Round-Robin & Weighted Algorithms**
  Distribute traffic evenly or based on weight preferences across backend targets.

* **Integrated Health Checks**
  Automatically route traffic only to healthy upstream services.

* **Horizontal Scalability**
  Add or remove backends dynamically, without restarting the gateway.



### Performance Optimization

* **HTTP Caching**
  Speed up responses and reduce load with route-based caching strategies.

* **Pluggable Cache Backends**

  * **In-Memory** for low-latency, single-node setups.
  * **Redis** for distributed, multi-node cache sharing.

* **Fine-Grained Control**

  * Respect standard `Cache-Control` headers.
  * Custom headers like `X-Cache-Status` for transparency.
  * Time or event-based cache invalidation strategies.


### Configuration & Extensibility

* **Modular Config Files**
  Split and organize routes and middleware using multiple `.yml` or `.yaml` files for clarity.

* **Live Configuration Reload**
  * Apply configuration changes on the fly — no server restarts required.
  * Dynamically enable or disable routes with zero downtime, allowing for flexible, real-time adjustments.

* **Kubernetes CRD Integration**

  * Manage routes, gateways, and middleware via Kubernetes-native CRDs.
  * GitOps-friendly for declarative and version-controlled configuration.

* **Declarative API Gateway Management**  
  Adopt a declarative approach to API Gateway Management, enabling you to:
  - Define routes and middleware programmatically for consistent, code-driven configuration.
  - Integrate GitOps workflows to version control your gateway configurations, ensuring traceable and automated deployments.

----

## Usage

### 1. Initialize Configuration

Generate a configuration file using the following command:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/config.yml
```
If no file is provided, a default configuration is created at /etc/goma/goma.yml.

### 2. Validate Configuration

Check your configuration file for errors:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway config check --config /etc/goma/config.yml

```

### 3. Start the Server with Custom Config

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway server --config /etc/goma/config.yml
```
### 4. Health Checks

Goma Gateway provides the following health check endpoints:
- Gateway Health:
  - `/readyz`
  - `/healthz`
- Routes Health: `/healthz/routes`

### 5. Simple Deployment with Docker Compose

Here’s a simple example of deploying Goma Gateway using Docker Compose:

Create a file named `config.yaml`:

```yaml
version: 2
gateway:
  # Timeout settings (in seconds)
  writeTimeout: 15 
  readTimeout: 15 
  idleTimeout: 30
  # Optional, default port 8080
  entryPoints:
    web:
      address: ":80"
    webSecure:
      address: ":443"
  # Route definitions
  routes:
    # First route definition - simple proxy to example.com
    - path: /                # Base path to match
      name: example           # Descriptive name for the route
      disabled: false         # Whether the route is disabled
      rewrite: ''             # Path rewrite rule (empty means no rewrite)
      destination: https://example.com  # Target URL for this route
      disableHostForwarding: true  # Don't forward the original host header
      cors: {}                # CORS settings
      middlewares:
        - basic-auth          # Apply basic authentication middleware
    # Second route definition
    - name: api             
      path: /                 
      disabled: false       
      hosts:                  # Host-based routing (virtual hosting)
        - app.example.com    # Only match requests for this host
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
      - /*                    # Apply to all paths
    rule:
      users:                  # Authorized users
        - admin:$2y$05$OyK52woO0JiM2GQOuUNw2e3xT30lBGXFTb5tn1xWeg3x/XexJNbia #password
        - user:password
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


### 6. Kubernetes deployment

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

## 💡 Why Use Goma Gateway?

**Goma Gateway** is more than just a reverse proxy — it's a modern, developer-friendly API Gateway designed to simplify, secure, and scale your service infrastructure. Here's why it stands out:


### ✅ **Simple, Declarative Configuration**

Configure routes, middleware, policies, and TLS in a clear and concise YAML format. Whether you prefer single-file or multi-file setups, Goma makes configuration intuitive and maintainable.

### 🔐 **First-Class Security Built-In**

Security isn't an afterthought. Goma ships with robust middleware for:

* Automatic HTTPS with **Let's Encrypt** or your own custom TLS certs.
* Built-in **Auth** support: Basic, JWT, OAuth, and ForwardAuth.
* Protection against **common exploits** like SQLi and XSS.
* Fine-grained **access control**, method restrictions, and bot detection.


### 🌐 **Multi-Domain & Dynamic Routing**

Host and route traffic across multiple domains effortlessly. Whether you're proxying REST APIs, WebSocket services, or static assets — Goma routes requests intelligently based on host and path.


### ⚙️ **Live Reload & GitOps-Ready**

No restarts needed. Goma supports **live configuration reloads**, making it ideal for CI/CD pipelines and GitOps workflows. Manage your gateway infrastructure declaratively and version everything.

### 📊 **Observability from Day One**

Goma offers full visibility into your traffic:

* **Structured Logging** with log level support.
* **Metrics & Dashboards** via Prometheus/Grafana integrations.
* **Built-in Rate Limiting** to throttle abusive traffic with optional Redis support.


### 🚀 **Performance Optimization**

Speed matters. Goma provides:

* **HTTP Caching** (in-memory or Redis) with intelligent invalidation.
* **Advanced Load Balancing** (round-robin, weighted) and health checks to keep your infrastructure resilient.

### ☸️ **Cloud-Native & Kubernetes-Friendly**

Integrate seamlessly with Kubernetes using **Custom Resource Definitions (CRDs)**. Manage routes, middleware, and gateways as native Kubernetes objects.

---

Whether you're building a secure public API, managing internal microservices, or modernizing legacy systems — **Goma Gateway** gives you the power and flexibility you need, without the complexity you don’t.

---
## Deployment

- Docker
- Kubernetes

## Contributing

The Goma Gateway project welcomes all contributors. We appreciate your help!


## Give a Star! ⭐

If you like or are using Goma Gateway, please give it a star. Thanks!

Please share.


## License

This project is licensed under the Apache 2.0 License. See the LICENSE file for details.


## Copyright

Copyright (c) 2024 Jonas Kaninda and contributors