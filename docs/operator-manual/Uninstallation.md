---
title: Uninstall
layout: default
parent: Operator Manual
nav_order: 5
---

# Uninstall

```sh
kubectl delete -f https://raw.githubusercontent.com/jkaninda/goma-operator/main/dist/install.yaml
```

### Force Gateway deletion

```shell
kubectl patch  gateways.gomaproj.github.io (gatewayName) -p '{"metadata":{"finalizers":[]}}' --type=merge
```

### Force gateway crd deletion

```shell
kubectl patch crd gateways.gomaproj.github.io -p '{"metadata":{"finalizers":[]}}' --type=merge

```