---
title: Overview
layout: home
nav_order: 1
---

# Goma Gateway
{:.no_toc}
**Goma Gateway** is a high-performance, security-focused API Gateway built for modern developers and cloud-native environments. With a powerful feature set, intuitive configuration, and first-class support for observability, Goma helps you route, secure, and scale traffic effortlessly.


The project is named after Goma, a vibrant city located in the eastern region of the Democratic Republic of the Congo — known for its resilience, beauty, and energy.


<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/logo.png" width="150" alt="Goma logo">


## Features

Goma Gateway is built for simplicity, flexibility, and high performance. It offers a comprehensive set of modern features to help you efficiently manage, route, and secure traffic across your services.

### Core Features

* **RESTful API Gateway Management**
  Manage your APIs easily with a clean, declarative configuration system designed for clarity and control.

* **Domain & Host-Based Routing**
  Route incoming requests based on domain or host to direct traffic to the appropriate services or environments.

* **Multi-Domain Support**
  Handle traffic across multiple domains with a unified, streamlined configuration approach.

* **Reverse Proxy**
  Seamlessly forward client requests to backend services, abstracting service details from clients.

* **Traffic Control & Rate Limiting**
  Protect your services from overload by controlling request rates and traffic flow.

* **WebSocket & gRPC Routing**
  Fully support real-time applications with native WebSocket and gRPC routing capabilities.

* **TCP/UDP Routing**
  Forward TCP, UDP, and gRPC traffic efficiently through the PassThrough entry point.

* **TLS & Certificate Management (Automatic & Custom)**
  Secure your communications with flexible TLS support, including automatic certificate provisioning and custom certificates.

* **Backend Error Interception**
  Intercept and handle backend errors gracefully to improve reliability and user experience.

* **Monitoring & Logging**
  Gain deep visibility into gateway operations with comprehensive monitoring and logging features.

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
