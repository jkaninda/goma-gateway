---
title: Uninstall
layout: default
parent: Operator Manual
nav_order: 5
---

# Uninstall

## Remove application resources

Delete your `Route`, `Middleware`, and `Gateway` resources before uninstalling the operator. This lets the controller clean up the gateway `Deployment`, `Service`, `ConfigMap`, and any HPA it owns.

```sh
kubectl delete routes,middlewares,gateways --all -A
```

## Remove the operator

```sh
kubectl delete -f https://raw.githubusercontent.com/jkaninda/goma-operator/main/dist/install.yaml
```

This removes the controller deployment, RBAC, the `goma-operator-system` namespace, and the CRDs.

## Force-remove a stuck Gateway

If a `Gateway` is stuck terminating because of finalizers, clear them manually:

```sh
kubectl patch gateways.gateway.jkaninda.dev <gateway-name> \
  -p '{"metadata":{"finalizers":[]}}' --type=merge
```

The same pattern works for `routes.gateway.jkaninda.dev` and `middlewares.gateway.jkaninda.dev`.

## Force-remove a stuck CRD

If a CRD itself is stuck terminating (typically because instances still reference finalizers):

```sh
kubectl patch crd gateways.gateway.jkaninda.dev \
  -p '{"metadata":{"finalizers":[]}}' --type=merge
```
