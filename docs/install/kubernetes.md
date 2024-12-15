---
title: Kubernetes
layout: default
parent: Installation
nav_order: 4
---

# Kubernetes Installation

Goma Gateway supports two installation types: **Simple Deployment** and **Advanced Deployment**.

## 1. Simple Deployment

The simple deployment uses standard Kubernetes deployment resources to run Goma Gateway.

### Deployment Guide

- Details on using Goma Gateway in Kubernetes can be found on the [Docker Hub repository](https://hub.docker.com/r/jkaninda/goma-gateway).
- Explore [Kubernetes deployment templates](https://github.com/jkaninda/goma-gateway/tree/main/examples) for built-in orchestration and scalability.

### Step 1: Generate Configuration File

Use the following command to create a configuration file:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/config.yml
```

If no configuration file is provided, Goma Gateway generates a default file at `/etc/goma/goma.yml`.

### Step 2: Create a ConfigMap

Define the configuration as a Kubernetes ConfigMap:
```shell
apiVersion: v1
kind: ConfigMap
metadata:
name: goma-config
data:
goma.yml: |
# Goma Gateway configurations
version: 1.0
gateway:
...
```
### Step 3: Deploy Goma Gateway

Create a Kubernetes Deployment using the following example:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goma-gateway
spec:
  selector:
    matchLabels:
      app: goma-gateway
  template:
    metadata:
      labels:
        app: goma-gateway
    spec:
      containers:
        - name: goma-gateway
          image: jkaninda/goma-gateway
          command: ["/usr/local/bin/goma", "server"]
          resources:
            limits:
              memory: "128Mi"
              cpu: "200m"
          ports:
            - containerPort: 8080
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          volumeMounts:
            - name: config
              mountPath: /etc/goma/
      volumes:
        - name: config
          configMap:
            name: goma-config
```


## 2. Advanced Deployment

The advanced deployment uses Goma Gateway’s Kubernetes Operator for more dynamic configuration management.

For detailed instructions, see the [Operator Manual](/goma-gateway/operator-manual/installation.html).
