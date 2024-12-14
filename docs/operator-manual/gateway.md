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
## Gateway
apiVersion: gomaproj.github.io/v1beta1
kind: Gateway
metadata:
   name: gateway-sample
spec:
   # Gateway version (use the latest release from the repository)
   gatewayVersion: latest # https://github.com/jkaninda/goma-gateway/releases

   ## Server Configuration
   server:
      tlsSecretName: '' # Optional: Specify a Kubernetes TLS secret name
      redis:
         addr: '' # Optional: Redis host (e.g., redis:6379)
         password: '' # Optional: Redis password
      writeTimeout: 10 # Request write timeout in seconds
      readTimeout: 15  # Request read timeout in seconds
      idleTimeout: 30  # Idle timeout in seconds
      logLevel: info   # Logging level (e.g., info, debug, warn, error)
      disableHealthCheckStatus: false # Enable or disable health check status
      disableKeepAlive: false         # Enable or disable KeepAlive connections
      enableMetrics: true             # Enable Prometheus metrics for monitoring

   ## Scaling and Resource Management
   replicaCount: 1 # Number of initial replicas
   resources:
      limits:
         cpu: 200m    # Maximum CPU allocation
         memory: 512Mi # Maximum memory allocation
      requests:
         cpu: 100m    # Minimum CPU allocation
         memory: 128Mi # Minimum memory allocation
   autoScaling:
      enabled: true # Enable Horizontal Pod Autoscaler
      minReplicas: 2 # Minimum number of replicas
      maxReplicas: 5 # Maximum number of replicas
      targetCPUUtilizationPercentage: 80 # Target CPU utilization
      targetMemoryUtilizationPercentage: 80 # Target memory utilization

   ## Node Affinity
   affinity: {}
```
