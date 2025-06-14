---
title: Overview
layout: home
nav_order: 2
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
