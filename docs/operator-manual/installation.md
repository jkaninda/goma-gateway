---
title: Installation
layout: default
parent: Operator Manual
nav_order: 1
---

# Installation

## Kubernetes Advanced deployment using CRDs and an Operator

**Install the CRDs and Operator into the cluster:**

```sh
kubectl apply -f https://raw.githubusercontent.com/jkaninda/goma-operator/main/dist/install.yaml
```

### Resources

- Gateway
- Middleware
- Route

### Resources order

- Gateway
- Middleware
- Route