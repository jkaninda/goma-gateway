---
title: Load Balancing
layout: default
parent: Monitoring and Performance
nav_order: 3
---


## Load Balancing

Goma Gateway includes built-in support for **round-robin** and **weighted** load balancing to efficiently distribute traffic across multiple backend services.

This ensures high availability, scalability, and optimal resource utilization in distributed environments.

---

###  Key Features

* **Round-Robin**: Evenly distributes incoming requests across available backends.
* **Weighted**: Allocates traffic proportionally based on assigned weights.
* **Health Checks**: Ensures only healthy backends receive traffic.
* **Scalable Architecture**: Supports seamless addition/removal of backend servers.
* **Smart Fallback**: Automatically removes failing backends from the rotation. — Not fully implemented

---

## Configuration Examples

### Round-Robin Load Balancing

This example defines three backend servers. Traffic is evenly distributed in a round-robin fashion (default behavior when no weights are specified):

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
        - endpoint: https://example.com
        - endpoint: https://example1.com
        - endpoint: https://example2.com
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
        - endpoint: https://example.com
          weight: 5
        - endpoint: https://example1.com
          weight: 2
        - endpoint: https://example2.com
          weight: 1
```

---

##  How It Works

* **Round-Robin**
  Goma cycles through available backend endpoints in order, ensuring each receives a similar number of requests.

* **Weighted Distribution**
  Each backend receives traffic proportionally to its configured `weight`. For example, a backend with weight `5` receives 5× more traffic than one with weight `1`.

* **Health Monitoring**
  Health checks prevent unhealthy backends from receiving requests. Use the `healthCheck` block to define check paths, intervals, timeouts, and valid status codes.

* **Dynamic Scaling**
  Backends can be added or removed at runtime without requiring a restart, supporting seamless horizontal scaling.

---

##  Notes

* The `target` field is ignored when `backends` are defined; it acts as a fallback.
* Always ensure the `healthCheck.path` exists on all backend services to avoid false negatives.
* Common healthy statuses include `200 OK` and optionally `404 Not Found` if used as an intentional empty state.
* Load balancing is performed per route, giving you granular control over traffic distribution.

---
