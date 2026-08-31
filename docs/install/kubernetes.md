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

#### Basic Deployment

```shell
kubectl apply -f https://raw.githubusercontent.com/jkaninda/goma-gateway/main/examples/k8s-basic-deployment.yaml
```

### Configuration Steps

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

### Step 4: Running as a Non-Root User (optional)

The image **runs as root by default**, so a gateway configured to listen on
ports 80 and 443 works without extra setup.

A Kubernetes deployment usually does not need that: the Service handles the
port mapping, and the example above already listens on the binary's default
`8080`. That means it can run unprivileged as **uid/gid 10001**, the `goma`
user that owns `/etc/goma`, `/etc/goma/extra` and `/etc/letsencrypt` in the
image:

```yaml
        - name: goma-gateway
          image: jkaninda/goma-gateway
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            runAsGroup: 10001
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]
```

Notes:

* **Keep the entrypoints above 1024.** A container without
  `CAP_NET_BIND_SERVICE` cannot bind 80 or 443. Expose them through the Service
  instead (`port: 80` → `targetPort: 8080`). If the gateway itself must listen
  on 80/443, add that one capability back:

  ```yaml
            capabilities:
              drop: ["ALL"]
              add: ["NET_BIND_SERVICE"]
  ```

* **PersistentVolumes must be writable by 10001.** For ACME, set
  `fsGroup: 10001` in the pod `securityContext` so the mounted volume is
  group-owned by the gateway.

* **Avoid `readOnlyRootFilesystem: true`** unless every writable path — the
  certificate directory in particular — is a mounted volume.

## 2. Advanced Deployment

The advanced deployment uses Goma Gateway’s Kubernetes Operator for more dynamic configuration management.

For detailed instructions, see the [Operator Manual](/operator-manual/installation.html).
