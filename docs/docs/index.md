---
title: Overview
sidebar_label: Overview
sidebar_position: 1
slug: /
---

# Goma Gateway
**Goma Gateway** is a high-performance, security-focused, cloud-native API Gateway. It puts security at the edge — automatic HTTPS, mTLS, built-in authentication, and exploit protection — and built to run where your services run: containers, Kubernetes, and dynamic, horizontally scaled environments. With declarative configuration, zero-downtime reloads, and first-class observability, Goma helps you route, secure, and scale traffic effortlessly.


The project is named after Goma, a vibrant city located in the eastern region of the Democratic Republic of the Congo — known for its resilience, beauty, and energy.


<img src="/img/logo.png" width="150" alt="Goma Gateway logo" />


## Features

More than just a reverse proxy: Goma Gateway secures, routes, and scales your traffic from a single **declarative configuration**, with enterprise-grade features and none of the enterprise complexity.

### Security & Access Control

* **[TLS with Automatic Certificate Management](./usermanual/tls.md)**
  * **Free, auto-generated certificates** via Let's Encrypt, with automatic renewal and storage.
  * **Custom TLS certificates**, falling back to auto-generation when none is provided.

* **[Mutual TLS (mTLS)](./usermanual/mtls.md)**
  Authenticate clients with certificates before traffic reaches your services.

* **Authentication Middleware**
  * Built-in **[Basic Auth](./middlewares/basic.md)**, **[JWT](./middlewares/jwt.md)**, **[OAuth](./middlewares/oauth.md)**, **[OpenID Connect](./middlewares/oidc.md)**, and **[LDAP](./middlewares/ldap.md)**.
  * **[ForwardAuth](./middlewares/forward-auth.md)** for external authorization services.

* **[Access Policy Enforcement](./middlewares/access-policy.md)**
  Allow or deny traffic based on route-specific rules (IP, headers, methods, etc.), with **[geo-blocking](./middlewares/geo-block.md)** by country.

* **Exploit Protection Middleware**
  Block common attack patterns such as SQL injection and cross-site scripting (XSS).

* **[Bot Detection](./middlewares/user-agent-block.md)**
  Identify and block traffic from known bots using user-agent analysis.

* **[Rate Limiting & Abuse Prevention](./middlewares/rate-limit.md)**
  * **In-memory** limits for single-instance deployments, or **Redis** for enforcement across many instances.
  * Automatic client banning for repeated violations.
  * Configurable thresholds and keys (IP address, API key, header, or cookie).

* **Request Hardening**
  * **[CORS](./usermanual/cors.md)** policies per route for controlled cross-origin access.
  * **[Body size limits](./middlewares/body-limit.md)** and explicit per-route HTTP method restrictions.
  * **[Custom header injection](./middlewares/request-headers.md)** for fine-grained request/response control.

### Cloud-Native by Design

* **[Kubernetes Operator](./operator-manual/index.md)**
  Manage gateways, routes, and middleware as Kubernetes-native `Gateway`, `Route`, and `Middleware` resources.

* **[Dynamic Configuration Providers](./usermanual/providers.md)**
  Load configuration from File, HTTP, Docker, and Kubernetes providers, and add or remove backends without restarting the gateway.

* **[Horizontal Scalability](./monitoring-and-performance/distributed-instances.md)**
  Run many stateless gateway instances, sharing rate-limit and cache state through Redis.

* **[Health & Readiness Endpoints](./usermanual/healthcheck.md)**
  `/healthz` and `/readyz` plug directly into orchestrator liveness and readiness probes.

* **Live Configuration Reload**
  Apply changes and enable or disable routes on the fly, with zero downtime.

* **GitOps-Ready, Modular Configuration**
  * Split routes and middleware across multiple `.yml` or `.yaml` files.
  * Version-control your gateway configuration for traceable, automated deployments.

### Routing & Traffic Management

* **Declarative Routing**
  Define routes, middleware, policies, and TLS in clear, maintainable YAML.

* **Domain & Host-Based Routing**
  Route requests by domain, host, or path, across multiple domains in one configuration.

* **Reverse Proxy**
  Forward client requests to backend services, abstracting service details from clients.

* **[WebSocket, gRPC, TCP & UDP](./usermanual/tcp-udp-grpc.md)**
  Native WebSocket and gRPC routing, plus TCP/UDP forwarding through the PassThrough entry point.

* **[Load Balancing](./monitoring-and-performance/load-balancing.md)**
  Round-robin and weighted algorithms, with integrated health checks that route only to healthy upstreams.

* **[Canary Deployments](./usermanual/canary-deployment.md)**
  * **Weighted Backends** – Gradually shift traffic between service versions using percentage-based routing.
  * **Conditional Routing** – Route requests based on user groups, headers, query parameters, or cookies for targeted rollouts.

* **[Regex URL Rewriting](./middlewares/rewrite-regex.md)**
  Modify request paths on the fly using regex rules.

* **[Backend Error Interception](./usermanual/error-interceptor.md)**
  Intercept and handle backend errors gracefully to improve reliability and user experience.

### Performance & Observability

* **[HTTP Caching](./middlewares/http-caching.md)**
  * **In-memory** for low-latency single-node setups, or **Redis** for distributed cache sharing.
  * Respects standard `Cache-Control` headers and exposes `X-Cache-Status` for transparency.
  * Time or event-based cache invalidation.

* **[Structured Logging](./monitoring-and-performance/logging.md)**
  Capture request/response details with configurable log levels (INFO, DEBUG, ERROR).

* **[Metrics](./monitoring-and-performance/monitoring.md)**
  Track response times, error rates, and throughput in **Prometheus**, with a prebuilt **Grafana** dashboard.

----
Architecture:
<img src="/img/goma-gateway.png" width="912" alt="Goma Gateway architecture" />

---

## Ecosystem

Goma Gateway is the **data plane**: fast, lightweight, and deliberately free of
heavy integrations. Management, service discovery and orchestration live in
separate projects around it.

| Project | Role |
|---|---|
| [Goma Admin](https://github.com/jkaninda/goma-admin) | Control plane — UI, multi-instance management, audit logs, Git sync |
| [Kubernetes Operator](https://github.com/jkaninda/goma-operator) | Manage gateways, routes and middleware as Kubernetes CRDs |
| [HTTP Provider](https://github.com/jkaninda/goma-http-provider) | Serve configuration to the gateway over a REST API |
| [Docker Provider](https://github.com/jkaninda/goma-docker-provider) | Generate configuration from container labels |
| [Kubernetes Provider](https://github.com/jkaninda/goma-k8s-provider) | Generate configuration from Kubernetes resources |

### Built on Goma Gateway

[**Miabi**](https://github.com/miabi-io/miabi) is a self-hosted,
developer-first Platform-as-a-Service for containerized apps — push from a Git
repo, a Docker image or a marketplace template, and it handles build, deploy,
domains, automatic SSL, databases, scaling, backups and monitoring.

Miabi runs **Goma Gateway as its edge gateway**. Every app deployed on the
platform is exposed through it, and the gateway is the only public listening
surface on the node: it terminates TLS, issues certificates, applies middleware
and routes traffic to the application containers. Miabi's control plane drives
it by writing route files into a watched directory, and remote clusters run
their own gateway that pulls its routes over HTTP.

It is a useful reference for anyone building a platform on top of Goma — see
[Providers](./usermanual/providers.md#miabi-paas-control-plane) for how the
integration works, and the
[Miabi architecture overview](https://docs.miabi.io/docs/architecture/overview).

---

We are open to receiving stars, PRs, and issues!



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