---
title: Gateway
layout: default
parent: Operator Manual
nav_order: 2
---

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

A simple example of gateway

```yaml
apiVersion: gomaproj.github.io/v1beta1
kind: Gateway
metadata:
  labels: {}
  name: gateway-sample
spec:
  # The version of Goma Gateway
  # See: https://github.com/jkaninda/goma-gateway/releases
  gatewayVersion: latest
  ## Server config
  server:
    # Kubernetes tls secret name
    tlsSecretName: '' #Optional, tls-secret
    #Redis configs for distributed rate limiting across multiple instances
    redis:
        addr: '' #Optional, redis:6379
        password: '' #Optional, password
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
      cpu: 200m
      memory: 512Mi
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
