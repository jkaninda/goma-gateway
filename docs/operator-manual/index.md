---
title: Operator Manual
layout: default
nav_order: 8
has_children: true
---

# Operator Manual

The **Goma Gateway Operator** brings Kubernetes-native management to Goma Gateway by introducing Custom Resource Definitions (CRDs) that model your API gateway configuration declaratively.

It defines three core resources:

- **Gateway** — platform-level configuration (deployment, scaling, TLS, certificate management).
- **Route** — traffic routing rules and backend definitions.
- **Middleware** — request/response processing logic (auth, rate limiting, headers, etc.).

This separation lets platform teams and application teams work independently while sharing the same declarative Kubernetes workflows.

## Highlights

- Declarative API gateway configuration via CRDs.
- GitOps-friendly (ArgoCD, Flux, etc.).
- Automatic TLS via the built-in ACME / Let's Encrypt manager (HTTP-01 and DNS-01 challenges).
- Dynamic configuration updates without pod restarts (powered by the embedded `goma-k8s-provider` sidecar).
- Built-in support for Redis-backed shared state, Prometheus metrics, and Horizontal Pod Autoscaling.
- Multiple dynamic configuration providers (Kubernetes CRDs, HTTP, Git).

## Architecture

The operator reconciles a `Gateway` resource into a complete runtime stack:

- `Deployment`
- `Service`
- `ConfigMap`
- `ServiceAccount` and `RBAC` resources
- Optional `HorizontalPodAutoscaler`

`Route` and `Middleware` resources are dynamically injected into the gateway via the embedded **goma-k8s-provider** sidecar, allowing live updates without restarting pods.

## Resources

| Resource | API Group | Purpose |
| --- | --- | --- |
| [Gateway](./gateway.md) | `gateway.jkaninda.dev/v1alpha1` | Platform configuration: pods, scaling, TLS, ACME, metrics. |
| [Route](./route.md) | `gateway.jkaninda.dev/v1alpha1` | Routing rules, backends, health checks. |
| [Middleware](./middlware.md) | `gateway.jkaninda.dev/v1alpha1` | Auth, rate-limiting, headers, redirects, etc. |

## Quick links

- Operator GitHub: [https://github.com/jkaninda/goma-operator](https://github.com/jkaninda/goma-operator)
- Operator examples: [https://github.com/jkaninda/goma-operator/tree/main/examples](https://github.com/jkaninda/goma-operator/tree/main/examples)
- Goma Gateway: [https://github.com/jkaninda/goma-gateway](https://github.com/jkaninda/goma-gateway)
