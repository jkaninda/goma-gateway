---
title: Installation
layout: default
parent: Operator Manual
nav_order: 1
---

# Installation

The **Goma Gateway Operator** ships as a single installable manifest containing the CRDs, RBAC, and the controller deployment. The operator runs in its own namespace (`goma-operator-system`) and watches `Gateway`, `Route`, and `Middleware` resources cluster-wide.

## Prerequisites

- Kubernetes ≥ 1.25
- `kubectl` configured against the target cluster
- Cluster-admin privileges (required to install CRDs and ClusterRoles)
- (Optional) `metrics-server` if you plan to use `autoScaling`

## Install the operator

Apply the bundled installer:

```sh
kubectl apply -f https://raw.githubusercontent.com/jkaninda/goma-operator/main/dist/install.yaml
```

This creates:

- The `goma-operator-system` namespace
- The `Gateway`, `Route`, and `Middleware` CRDs (group: `gateway.jkaninda.dev`, version: `v1alpha1`)
- The controller `Deployment`, `ServiceAccount`, and RBAC bindings
- A metrics `Service` for the controller

Wait for the controller to become ready:

```sh
kubectl -n goma-operator-system rollout status deploy/goma-operator-controller-manager
```

Verify the CRDs are installed:

```sh
kubectl get crds | grep gateway.jkaninda.dev
```

Expected output:

```
gateways.gateway.jkaninda.dev
middlewares.gateway.jkaninda.dev
routes.gateway.jkaninda.dev
```

## Pin a specific version

Replace `main` with a release tag for reproducible installs:

```sh
kubectl apply -f https://raw.githubusercontent.com/jkaninda/goma-operator/v0.1.0/dist/install.yaml
```

## Install via Kustomize / GitOps

Reference the upstream `dist/install.yaml` from your overlay, or vendor it into your repository for ArgoCD / Flux:

```yaml
# kustomization.yaml
resources:
  - https://raw.githubusercontent.com/jkaninda/goma-operator/main/dist/install.yaml
```

## Resources

The operator reconciles three CRDs. They follow this logical ordering — apply the **Gateway** first, then the **Middlewares** it references, then the **Routes** that bind them together:

1. [Gateway](./gateway.md) — the platform-level configuration that creates the gateway `Deployment`, `Service`, and `ConfigMap`.
2. [Middleware](./middlware.md) — reusable request/response processors (auth, rate limiting, headers, etc.).
3. [Route](./route.md) — the actual routing rules that attach to a `Gateway` and apply `Middlewares`.

> The `goma-k8s-provider` sidecar (enabled by default) hot-reloads `Route` and `Middleware` changes into the gateway without pod restarts. You may apply resources in any order and the operator will reconcile them.

## What's next

- Apply a minimal Gateway from the [Gateway documentation](./gateway.md).
- Browse the operator's runnable [examples](https://github.com/jkaninda/goma-operator/tree/main/examples) for ready-to-use manifests covering ACME, autoscaling, JWT, rate limiting, and more.
