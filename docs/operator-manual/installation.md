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

{: .warning }
The Kubernetes Operator for Goma Gateway is not compatible with the current version of Goma Gateway. Please use Kubernetes native deployment method instead. See [Installation](./installation.md) for more details.


### Resources

- Gateway
- Middleware
- Route

### Resources order

- Gateway
- Middleware
- Route