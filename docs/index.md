---
title: Overview
layout: home
nav_order: 1
---

# Goma Gateway
{:.no_toc}
Goma Gateway is a lightweight High-Performance Declarative API Gateway Management.

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/logo.png" width="150" alt="Goma logo">


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
- **Round-Robin Algorithm**: Distribute incoming requests evenly across backend servers to ensure optimal resource utilization.
- **Health Checks**: Regularly monitor server health.
- **Scalability**: Easily scale horizontally by adding or removing backend servers without downtime.


#### **HTTP Caching**
- **Cache Implementation**: Enable HTTP caching for routes to improve response times and reduce server load.
- **Cache Storage Options**:
  - **In-Memory Cache**: Suitable for single-instance applications or temporary caching.
  - **Redis Cache**: Ideal for distributed caching across multiple instances.
  - **Cache Control Headers**: Support for `Cache-Control`, `X-Cache-Status`, and `Last-Modified` headers for fine-grained cache management.
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
Architecture:
<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/goma-gateway.png" width="912" alt="Goma archi">

We are open to receiving stars, PRs, and issues!


{: .fs-6 .fw-300 }

---

The [jkaninda/goma-gateway](https://hub.docker.com/r/jkaninda/goma-gateway) Docker image can be deployed on Docker, Docker in Swarm mode, and Kubernetes. 


## Available image registries

This Docker image is published to both Docker Hub and the GitHub container registry.
Depending on your preferences and needs, you can reference both `jkaninda/goma-gateway` as well as `ghcr.io/jkaninda/goma-gateway`:

```
docker pull jkaninda/goma-gateway
docker pull ghcr.io/jkaninda/goma-gateway
```

Documentation references Docker Hub, but all examples will work using ghcr.io just as well.


## References

We decided to publish this image as a simpler and more lightweight because of the following requirements:

- The original image is based on `Alpine`, making it heavy.
- This image is written in Go.
- `arm64` and `arm/v7` architectures are supported.
- Docker in Swarm mode is supported.
- Kubernetes is supported.
