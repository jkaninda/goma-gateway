---
title: Gateway
sidebar_label: Gateway
sidebar_position: 2
---

# Gateway

The **Gateway** custom resource is the platform-level entry point. A single `Gateway` object reconciles into a complete runtime stack: a `Deployment` running Goma Gateway, a `Service` exposing it, a `ConfigMap` holding its static configuration, and — when enabled — an `HorizontalPodAutoscaler` and the `goma-k8s-provider` sidecar that hot-reloads `Route` and `Middleware` changes.

- **API group:** `gateway.jkaninda.dev`
- **Version:** `v1alpha1`
- **Kind:** `Gateway`

## How it works

When a `Gateway` is applied, the operator creates the following resources, all named after the `Gateway`:

| Resource | Purpose |
| --- | --- |
| `Deployment` | Runs the gateway container (and the `goma-k8s-provider` sidecar by default). |
| `Service` | Exposes container ports `8080` (HTTP) and `8443` (HTTPS). Configurable via `spec.service`. |
| `ConfigMap` | Holds the static portion of the gateway config. |
| `HorizontalPodAutoscaler` | Created when `spec.autoScaling.enabled: true`. |

The container always listens on `8080` and `8443`. The `Service` ports are independent — set `spec.service.httpPort: 80` and `httpsPort: 443` for Ingress-style exposure on standard ports.

## Minimal example

The smallest valid `Gateway`. Defaults are sensible: a single replica, ClusterIP `Service`, and the K8s provider sidecar enabled.

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Gateway
metadata:
  name: gateway
  namespace: default
spec:
  image: jkaninda/goma-gateway:latest
  replicas: 1
  server:
    logLevel: info
```

## Exposing the gateway

The `spec.service` block controls how the gateway is reached from outside the cluster.

### LoadBalancer (cloud)

```yaml
spec:
  replicas: 2
  service:
    type: LoadBalancer
    httpPort: 80
    httpsPort: 443
    externalTrafficPolicy: Local   # preserve client source IPs
    annotations:
      service.beta.kubernetes.io/aws-load-balancer-type: nlb
```

### NodePort (bare metal / dev)

```yaml
spec:
  service:
    type: NodePort
    httpPort: 8080
    httpsPort: 8443
    httpNodePort: 30080
    httpsNodePort: 30443
```

### Ingress in front

Leave the `Service` as the default `ClusterIP` and route to it from your existing Ingress controller. Ports remain `8080` / `8443`.

## TLS

Goma Gateway supports two TLS strategies, which can be combined.

### 1. Bring-your-own certificates

Reference one or more Kubernetes TLS secrets (`type: kubernetes.io/tls`) in `spec.server.tls`:

```yaml
spec:
  server:
    tls:
      - secretName: example-com-tls
      - secretName: api-example-com-tls
```

### 2. Built-in ACME / Let's Encrypt

Enable the gateway's certificate manager and issue certs automatically.

**HTTP-01** (gateway must be publicly reachable on port 80):

```yaml
spec:
  service:
    type: LoadBalancer
    httpPort: 80
    httpsPort: 443
  certManager:
    provider: acme
    acme:
      email: ops@example.com
      termsAccepted: true
      challengeType: http-01
      # For testing, switch to staging to avoid rate limits:
      # directoryUrl: https://acme-staging-v02.api.letsencrypt.org/directory
```

**DNS-01** (required for wildcard certs, no public ingress needed). Supported `dnsProvider` value: `cloudflare` (the gateway accepts `route53` but does not implement it yet):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: cloudflare-credentials
type: Opaque
stringData:
  apiToken: REPLACE_ME
---
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Gateway
metadata:
  name: gateway-wildcard
spec:
  certManager:
    provider: acme
    acme:
      email: ops@example.com
      termsAccepted: true
      challengeType: dns-01
      dnsProvider: cloudflare
      credentialsSecret: cloudflare-credentials
```

:::warning[Known limitation]
The generated config references the DNS token as `${GOMA_CREDENTIALS_API_TOKEN}`, but the current operator does not yet inject `credentialsSecret` into the gateway pod, so DNS-01 issuance does not work out of the box.
:::

### Multiple certificate providers

:::note
`certManager.providers`, `certManager.defaultProvider` and the Route's `tls.provider` require an operator release newer than `v0.2.0`.
:::

Declare named providers when different routes need different ACME accounts or challenge types. Each provider gets its own ACME account and storage file. A [Route](./route.md#per-route-tls) picks one with `spec.tls.provider`; routes that name none use `defaultProvider`.

```yaml
spec:
  certManager:
    defaultProvider: letsencrypt
    providers:
      letsencrypt:
        type: acme
        acme:
          email: ops@example.com
          challengeType: http-01
      letsencrypt-dns:
        type: acme
        acme:
          email: ops@example.com
          challengeType: dns-01
          dnsProvider: cloudflare
          credentialsSecret: cloudflare-credentials
```

When `providers` is set, the top-level `provider` / `acme` fields are ignored.

## Scaling

### Static replicas

```yaml
spec:
  replicas: 3
```

### Horizontal Pod Autoscaler

Requires the `metrics-server` to be installed in the cluster.

```yaml
spec:
  replicas: 2
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 1
      memory: 512Mi
  autoScaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

## Shared state with Redis

When running multiple replicas, Redis lets stateful middlewares such as rate limiting share state across pods. See [Distributed Instances](../monitoring-and-performance/distributed-instances.md).

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Gateway
metadata:
  name: gateway
spec:
  replicas: 3
  server:
    redis:
      addr: redis.default.svc.cluster.local:6379
      password: changeme
```

`redis.password` is a plain string rendered into the gateway `ConfigMap`; the `Gateway` CRD has no Secret reference for it.

## Observability

Prometheus metrics are off by default. Enable and optionally protect them (see [Monitoring](../monitoring-and-performance/monitoring.md) for the exposed metrics):

```yaml
spec:
  server:
    monitoring:
      enableMetrics: true
      metricsPath: /metrics
      host: metrics.internal.example.com   # restrict by Host header
      middleware:
        metrics:
          - metrics-basic-auth              # protect /metrics with a Middleware CR
```

`/healthz` and `/readyz` are always enabled — the operator wires them to the pod's liveness and readiness probes.

## Dynamic configuration providers

By default the operator injects the `goma-k8s-provider` sidecar, which watches `Route` and `Middleware` CRs and hot-reloads them into the gateway. You can disable it (in which case routes are delivered through the static `ConfigMap`, requiring a pod restart on changes) or use HTTP / Git providers instead.

```yaml
spec:
  providers:
    kubernetes:
      enabled: true        # default
      image: jkaninda/goma-k8s-provider:latest
    http:
      enabled: false
      endpoint: https://config.example.com/goma.yaml
      interval: 60s
    git:
      enabled: false
      url: https://github.com/example/gateway-config.git
      branch: main
      path: config
      interval: 60s
      auth:
        type: token
        secretName: git-credentials
```

:::warning[Known limitation]
The current operator does not yet mount the Secrets named by `http.headersSecret` or `git.auth.secretName` into the gateway pod, so authenticated HTTP and Git providers do not work out of the box.
:::

## Spec reference

| Field | Type | Description |
| --- | --- | --- |
| `image` | string | Gateway container image. Default: `jkaninda/goma-gateway:latest`. |
| `replicas` | int32 | Number of gateway pods. Default: `1`. |
| `imagePullSecrets` | []LocalObjectReference | Secrets used to pull the gateway image. |
| `resources` | ResourceRequirements | CPU/memory requests and limits for the gateway container. |
| `affinity` | corev1.Affinity | Pod scheduling constraints. |
| `autoScaling` | object | HPA configuration (see below). |
| `server` | object | Server runtime configuration (see below). |
| `service` | object | Kubernetes Service exposure (see below). |
| `certManager` | object | Built-in ACME / Let's Encrypt certificate manager. |
| `providers` | object | Dynamic configuration providers (Kubernetes sidecar, HTTP, Git). |

### `spec.server`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `logLevel` | enum | `info` | One of `info`, `debug`, `trace`, `off`. |
| `timeouts.read` | int | `30` | Read timeout in seconds. |
| `timeouts.write` | int | `60` | Write timeout in seconds. |
| `timeouts.idle` | int | `90` | Idle timeout in seconds. |
| `tls[].secretName` | string | — | Name of a `kubernetes.io/tls` Secret. |
| `redis.addr` | string | — | Redis `host:port`. |
| `redis.password` | string | — | Redis password (consider using a Secret). |
| `monitoring.enableMetrics` | bool | `false` | Expose Prometheus metrics. |
| `monitoring.metricsPath` | string | `/metrics` | Path of the metrics endpoint. |
| `monitoring.host` | string | — | Restrict `/metrics` to this Host header (`/healthz` and `/readyz` are never host-restricted). |
| `monitoring.middleware.metrics` | []string | — | Middleware CR names applied to `/metrics`. |
| `networking.dnsCache.ttl` | int | `300` | DNS cache TTL in seconds (gateway default when unset). |
| `networking.transport.maxIdleConns` | int | `512` | Max idle connections. |
| `networking.transport.maxIdleConnsPerHost` | int | `256` | Max idle connections per host. |
| `networking.transport.maxConnsPerHost` | int | `256` | Max total connections per host. |

The `Gateway` CRD exposes only the fields above. Other gateway settings — for example `log.format`, `monitoring.visitorTTL`, `analytics`, `reload`, or `networking.dnsCache.resolver` — are not part of the CRD; the API server rejects or prunes unknown fields.

### `spec.service`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `type` | enum | `ClusterIP` | `ClusterIP`, `NodePort`, or `LoadBalancer`. |
| `httpPort` | int32 | `8080` | Service-level HTTP port. Set to `80` for Ingress-style exposure. |
| `httpsPort` | int32 | `8443` | Service-level HTTPS port. Set to `443` for Ingress-style exposure. |
| `httpNodePort` | int32 | — | NodePort for HTTP (`type: NodePort` only). |
| `httpsNodePort` | int32 | — | NodePort for HTTPS (`type: NodePort` only). |
| `loadBalancerIP` | string | — | Request a specific static IP (cloud-dependent). |
| `loadBalancerSourceRanges` | []string | — | Restrict access to specific CIDRs. |
| `loadBalancerClass` | string | — | Select a specific LB implementation (e.g. `service.k8s.aws/nlb`). |
| `externalTrafficPolicy` | enum | `Cluster` | `Cluster` or `Local` (Local preserves client source IPs). |
| `sessionAffinity` | enum | `None` | `None` or `ClientIP`. |
| `annotations` | map | — | Merged onto the Service (use for cloud LB tuning). |
| `labels` | map | — | Merged onto the Service. |
| `ipFamilyPolicy` | enum | — | `SingleStack`, `PreferDualStack`, or `RequireDualStack`. |
| `ipFamilies` | []string | — | List of IP families: `IPv4`, `IPv6`. |

### `spec.certManager`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `defaultProvider` | string | — | Entry in `providers` used by Routes that set no `tls.provider`. |
| `providers.<name>.type` | enum | `acme` | Currently only `acme` is supported. |
| `providers.<name>.acme` | object | — | Same fields as `acme` below. |
| `provider` | enum | `acme` | Single-provider form. Currently only `acme` is supported. Prefer `providers`. |
| `acme.email` | string | — | **Required.** Contact email for the ACME account. |
| `acme.directoryUrl` | string | Let's Encrypt prod | ACME directory endpoint. |
| `acme.termsAccepted` | bool | `true` | Acceptance of the ACME provider's ToS. |
| `acme.challengeType` | enum | `http-01` | `http-01` or `dns-01` (use `dns-01` for wildcards). |
| `acme.dnsProvider` | string | — | DNS-01 provider: `cloudflare` (the only one implemented by the gateway). |
| `acme.credentialsSecret` | string | — | Secret with the DNS provider credentials (key `apiToken`). |

### `spec.autoScaling`

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | Whether the HPA is created. |
| `minReplicas` | int32 | `1` | Lower bound. |
| `maxReplicas` | int32 | `10` | Upper bound. |
| `targetCPUUtilizationPercentage` | int32 | — | Target average CPU. |
| `targetMemoryUtilizationPercentage` | int32 | — | Target average memory. |

### `spec.providers`

| Field | Type | Description |
| --- | --- | --- |
| `kubernetes.enabled` | bool | Enables the `goma-k8s-provider` sidecar (default: `true`). |
| `kubernetes.image` | string | Sidecar image. Default: `jkaninda/goma-k8s-provider:latest`. |
| `http.enabled` | bool | Enables a remote HTTP provider. |
| `http.endpoint` | string | URL of the remote config. |
| `http.interval` | string | Pull interval. Default: `60s`. |
| `http.timeout` | string | Per-request timeout. Default: `10s`. |
| `http.headers` | map | Extra request headers. |
| `http.headersSecret` | string | Secret with header values referenced via `${VAR}`. |
| `http.insecureSkipVerify` | bool | Skip TLS verification of the endpoint. |
| `http.retryAttempts` | int | Retries on failure. Default: `3`. |
| `http.retryDelay` | string | Delay between retries. Default: `2s`. |
| `http.cacheDir` | string | Where fetched responses are cached. |
| `git.enabled` | bool | Enables the Git provider. |
| `git.url` | string | Repository URL. |
| `git.branch` | string | Branch to check out. Default: `main`. |
| `git.path` | string | Subdirectory inside the repo. |
| `git.interval` | string | Pull interval. Default: `60s`. |
| `git.cloneDir` | string | Local clone directory. |
| `git.auth` | object | `type` (`token`/`basic`/`ssh`) and `secretName`. The Secret holds `token`, `username`/`password`, or `ssh-privatekey`. |

## Status

`kubectl get gateway` shows the address (when a `LoadBalancer` is provisioned), replica counts, and route count:

```
NAME      TYPE           ADDRESS         REPLICAS   READY   ROUTES   AGE
gateway   LoadBalancer   34.120.10.42    3          3       5        4m
```

Inspect full conditions with:

```sh
kubectl describe gateway gateway
```
