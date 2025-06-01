# Goma Gateway - simple Lightweight High-Performance Declarative API Gateway Management.

```
   _____                       
  / ____|                      
 | |  __  ___  _ __ ___   __ _ 
 | | |_ |/ _ \| '_ ` _ \ / _` |
 | |__| | (_) | | | | | | (_| |
  \_____|\___/|_| |_| |_|\__,_|
                               
```
---

[![Tests](https://github.com/jkaninda/goma-gateway/actions/workflows/test.yml/badge.svg)](https://github.com/jkaninda/goma-gateway/actions/workflows/test.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jkaninda/goma-gateway)](https://goreportcard.com/report/github.com/jkaninda/goma-gateway)
[![Go](https://img.shields.io/github/go-mod/go-version/jkaninda/goma-gateway)](https://go.dev/)
[![Go Reference](https://pkg.go.dev/badge/github.com/jkaninda/goma-gateway.svg)](https://pkg.go.dev/github.com/jkaninda/goma-gateway)
[![GitHub Release](https://img.shields.io/github/v/release/jkaninda/goma-gateway)](https://github.com/jkaninda/goma-gateway/releases)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jkaninda/goma-gateway?style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/jkaninda/goma-gateway?style=flat-square)

Goma Gateway is a lightweight High-Performance Declarative API Gateway Management.


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

It's designed to be straightforward and efficient, offering a rich set of features, including:

### Core Features
- **RESTful API Gateway Management**  
  Simplify the management of your API Gateway with powerful tools.

- **Domain/Host-Based Request Routing**  
  Route requests based on specific domains or hosts.

- **Multi-Domain Request Routing**  
  Handle requests across multiple domains seamlessly.

- **Reverse Proxy**  
  Efficiently forward client requests to backend servers.

- **WebSocket Proxy**  
  Enable real-time communication via WebSocket support.

### Security and Control
- **Cross-Origin Resource Sharing (CORS)**  
  Define and manage cross-origin policies for secure interactions.

- **Custom Headers**  
  Add and modify headers to meet specific requirements.

- **Backend Errors Interceptor**  
  Catch and handle backend errors effectively.

- **Block Common Exploits Middleware**
  - Detect patterns indicating SQL injection attempts.
  - Identify basic cross-site scripting (XSS) attempts.

- **Authentication Middleware**
  - Support for **ForwardAuth** with client authorization based on request results.
  - **Basic-Auth** and **OAuth** authentication mechanisms.
- **Access Policy Middleware**
    - Control route access by either `allowing` or `denying` requests based on defined rules.
- **Regex Support for URL Rewriting**
    - Rewrite URL paths using regex patterns.
- **Bot Detection Middleware**
    - Protect your route from bots by blocking requests from known bots.

### Monitoring and Performance

#### **Logging**
- **Comprehensive Logging**: Implement detailed logging for all incoming requests and outgoing responses.
- **Log Levels**: Support multiple log levels (e.g., INFO, DEBUG, ERROR) to capture varying degrees of detail.


### **Metrics**  
- **Performance Monitoring**: Collect and analyze key performance metrics such as response times, error rates, and throughput.
- **Real-Time Dashboards**: Integrate with monitoring tools (e.g., Prometheus, Grafana) to visualize metrics in real-time.

#### **Rate Limiting**
- **In-Memory Rate Limiting**:
  - Throttle requests based on client IP addresses using in-memory storage.
  - Suitable for single-instance applications or low-traffic scenarios.
- **Distributed Rate Limiting**:
  - Use Redis for scalable, client IP-based rate limiting across multiple application instances.
  - Configure rate limits (e.g., requests per minute) to prevent abuse and ensure fair usage.

#### **Load Balancing**

- **Round-Robin Algorithm**: Distributes incoming requests evenly across backend servers, ensuring balanced resource utilization.
- **Weighted Algorithm**: Distributes incoming requests based on predefined weights, allowing for prioritized traffic allocation to specific servers.
- **Health Checks**: Continuously monitors the health of backend servers to ensure only healthy servers receive traffic.
- **Scalability**: Enables seamless horizontal scaling by adding or removing backend servers without downtime.
- **Integrated Health Checks**: Automatically monitors the health of backend servers to maintain high availability.




#### **HTTP Caching**
- **Cache Implementation**: Enable HTTP caching for routes to improve response times and reduce server load.
- **Cache Storage Options**:
  - **In-Memory Cache**: Suitable for single-instance applications or temporary caching.
  - **Redis Cache**: Ideal for distributed caching across multiple instances.
  - **Cache Control Headers**: Support for `Cache-Control`, `and X-Cache-Status` headers for fine-grained cache management.
  - **Cache Invalidation**: Implement strategies to invalidate stale cache entries (e.g., time-based or event-based invalidation).

### Configuration and Flexibility

- **Support for Multiple Route and Middleware Configuration Files**  
  Easily organize and manage routes by splitting them across multiple `.yml` or `.yaml` files for improved maintainability and clarity.

- **Dynamic Configuration Reload**
  - Reload configurations seamlessly without server restarts, ensuring uninterrupted service.
  - Dynamically enable or disable routes with zero downtime, allowing for flexible, real-time adjustments.

- **TLS Integration**  
  Secure communication through built-in TLS support, enhancing data protection and user trust.

- **HTTP Method Restrictions**  
  Enforce HTTP method restrictions on specific routes, providing granular control and improved security.

- **Kubernetes CRD Integration**
  - Leverage Kubernetes-native Custom Resource Definitions (CRDs) for streamlined management of gateways, routes, and middleware.
  - Define and configure gateways, routes, and middleware directly within Kubernetes manifests for seamless operator-focused workflows.

- **Declarative API Gateway Management**  
  Adopt a declarative approach to API gateway management, enabling you to:
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

Here’s an example of deploying Goma Gateway using Docker Compose:

```yaml
# config.yaml
version: 2
gateway:
  writeTimeout: 15
  readTimeout: 15
  idleTimeout: 30
  routes:
    - path: /
      name: example
      disabled: false
      hosts: []
      rewrite: ''
      destination: https://example.com
      disableHostForwarding: true
      cors: {}
      middlewares:
        - basic-auth
    - name: load-balancer
      path: /load-balancer
      disabled: false
      hosts: []
      rewrite: /
      backends:
       - endpoint: https://backend1.example.com
         weight: 1 # Optional can be omitted
       - endpoint:  https://backend2.example.com
         weight: 3 # Optional can be omitted
      healthCheck:
       path: /
       interval: 15s
       timeout: 10s
       healthyStatuses:
         - 200
         - 404
      middlewares: []
middlewares:
  - name: basic-auth
    type: basic
    paths:
      - /*
    rule:
      users: 
        - admin:$2y$05$OyK52woO0JiM2GQOuUNw2e3xT30lBGXFTb5tn1xWeg3x/XexJNbia # bcrypt hash
        - user:password # Plaintext password
      
```

```shell
# compose.yaml
services:
  goma-gateway:
    image: jkaninda/goma-gateway
    command: server -c config.yaml
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./:/etc/goma/
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

Copyright (c) 2024 Jonas Kaninda