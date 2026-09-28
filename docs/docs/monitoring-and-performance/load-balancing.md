---
title: Load Balancing
sidebar_label: Load Balancing
sidebar_position: 3
---


## Load Balancing

Goma Gateway includes built-in support for **round-robin** and **weighted** load balancing to efficiently distribute traffic across multiple backend services.

This ensures high availability, scalability, and optimal resource utilization in distributed environments.

---

###  Key Features

* **Round-Robin**: Evenly distributes incoming requests across available backends.
* **Weighted**: Allocates traffic proportionally based on assigned weights.
* **Health Checks**: Backends that fail their health check are taken out of rotation until they pass again.
* **Canary Routing**: Backends can also be selected by request attributes; see [Canary Deployment](../usermanual/canary-deployment.md).

---

## Configuration Examples

### Round-Robin Load Balancing

This example defines three backend servers. Traffic is evenly distributed in a round-robin fashion (the default when no backend sets a `weight`):

```yaml
version: 2
gateway:
  routes:
    - name: example-route
      path: /
      rewrite: /
      hosts:
        - example.com
        - example.localhost
      methods: []
      healthCheck:
        path: "/"
        interval: 30s
        timeout: 10s
        healthyStatuses: [200, 404]
      backends:
        - endpoint: https://api.example.com
        - endpoint: https://api-2.example.com
        - endpoint: https://api-3.example.com
```

---

### Weighted Load Balancing

In this setup, traffic is distributed based on weight values. Higher weights receive a greater share of requests:

```yaml
version: 2
gateway:
  routes:
    - name: weighted-example
      path: /
      rewrite: /
      hosts:
        - example.com
      methods: []
      healthCheck:
        path: "/"
        interval: 30s
        timeout: 10s
        healthyStatuses: [200, 404]
      backends:
        - endpoint: https://api.example.com
          weight: 5
        - endpoint: https://api-2.example.com
          weight: 2
        - endpoint: https://api-3.example.com
          weight: 1
```

---

##  How It Works

* **Round-Robin**
  Goma cycles through the available backend endpoints in order, so each receives a similar number of requests.

* **Weighted Distribution**
  As soon as one backend sets a `weight`, the route switches to weighted selection. Each request picks a backend at random with probability `weight / sum(weights)`, so over time a backend with weight `5` receives about 5× more traffic than one with weight `1`. A backend without a `weight` receives no traffic in this mode.

* **Health Monitoring**
  When the route has a `healthCheck` block, each backend is probed at `healthCheck.path` every `interval`. A backend that fails one check is removed from the rotation, and it is added back as soon as a check succeeds. If every backend is down, the gateway answers `503 Service Unavailable`. See [Health check](../usermanual/healthcheck.md) for the check options.

* **Configuration Changes**
  Backends can be added or removed by reloading the configuration (file watch, providers, or the reload endpoint) without restarting the gateway.

---

##  Notes

* When `backends` is set, `target` is ignored; it is not used as a fallback.
* A route with a single backend (or only a `target`) is always proxied, whatever its health check reports.
* Health state is tracked per backend `endpoint` exactly as configured; an endpoint may include a path or trailing slash, and `healthCheck.path` is appended to it with a single `/`.
* Make sure `healthCheck.path` exists on every backend. List any non-`2xx`/`3xx` status that should count as healthy in `healthyStatuses` (for example `404` if the path intentionally returns it).
* Load balancing is performed per route, giving you granular control over traffic distribution.

---
