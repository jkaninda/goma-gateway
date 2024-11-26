---
title: Kubernetes Advanced deployment
layout: default
parent: Installation
nav_order: 5
---

# Kubernetes Advanced deployment using CRDs and an Operator

**Install the CRDs and Operator into the cluster:**

```sh
kubectl apply -f https://raw.githubusercontent.com/jkaninda/goma-operator/main/dist/install.yaml
```

## Resources

- Gateway
- Route
- Middleware

## Gateway
The **Gateway** serves as the entry point to the server, handling and routing incoming traffic.

### Installation Details

When a Gateway is installed, it automatically creates the following Kubernetes resources, all with the same name as the Gateway:

- **Service**
- **ConfigMap**
- **Deployment**

### Service Ports

The service exposes the following ports:

- **HTTP**: `8080`
- **HTTPS**: `8443`

### Exposing the Gateway Outside the Cluster

To expose your Gateway outside the cluster, you have the following options:

1. **Create an Ingress resource**:  
   Configure an Ingress to route external traffic to your Gateway.

2. **Change the Service Type**:  
   Patch the Gateway's service to change its type (e.g., to `LoadBalancer` or `NodePort`) for external accessibility.


```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Gateway
metadata:
  labels: {}
  name: gateway-sample
spec:
  # The version of Goma Gateway
  # See: https://github.com/jkaninda/goma-gateway/releases
  gatewayVersion: 0.2.2 
  ## Server config
  server:
    writeTimeout: 10
    readTimeout: 15
    idleTimeout: 30
    logLevel: info
    disableHealthCheckStatus: false
    disableKeepAlive: false
    enableMetrics: true
  replicaCount: 1
  resources:
    limits:
      cpu: 100m
      memory: 128Mi
    requests:
      cpu: 100m
      memory: 128Mi
  # Enable auto scaling
  autoScaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 5
    targetCPUUtilizationPercentage: 80
    targetMemoryUtilizationPercentage: 80
  affinity: {}
```

## Middleware

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Middleware
metadata:
  name: basic-middleware-sample
spec:
    type: basic
    paths:
      - /admin/*
    rule:
        username: admin
        password: admin
```

## Route

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Route
metadata:
  labels: {}
  name: route-sample
spec:
  gateway: gateway-sample
  routes:
  - path: /
    name: Example
    hosts: []
    rewrite: /
    methods:
      - GET
      - POST
      - PUT
    destination: https://example.com
    backends: []
    insecureSkipVerify: false
    healthCheck:
      path: /
      interval: 10s
      timeout: 10s
      healthyStatuses:
        - 200
        - 404
    cors:
      origins: []
      headers: {}
    rateLimit: 15
    disableHostFording: true
    interceptErrors: []
    blockCommonExploits: false
    ## Middleware names
    middlewares:
      - basic-middleware-sample
```

## Uninstall

```sh
kubectl delete -f https://raw.githubusercontent.com/jkaninda/goma-operator/main/dist/install.yaml
```