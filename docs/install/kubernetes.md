---
title: Kubernetes
layout: default
parent: Installation
nav_order: 4
---

# Kubernetes Installation

Goma Gateway has two types of installations: simple and advanced.

## 1. Simple Deployment

Simple deployment is to deploy Goma Gateway using Kubernetes deployment resources.

Details about how to use Goma in Kubernetes can be found on the hub.docker.com repo hosting the image: Goma.
We also have some cool examples with [Kubernetes deployment template](https://github.com/jkaninda/goma-gateway/tree/main/examples) with built-in orchestration and scalability.

## 1. Generate a configuration file

You can generate the configuration file using `config init --output /etc/goma/config.yml` command.

The default configuration is automatically generated if any configuration file is not provided, and is available at `/etc/goma/goma.yml`

```shell
docker run --rm  --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/config.yml
```

## 2. Create ConfigMap

```yaml
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
## 3. Create Kubernetes deployment

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
          command: ["/usr/local/bin/goma","server"]
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

Advanced deployment is to deploy Goma Gateway using its Kubernetes Operator.

See Operator Manual
