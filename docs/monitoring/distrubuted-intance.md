---
title: Distributed instances
layout: default
parent: Monitoring and Performance
nav_order: 4
---



## Distributed Instances

Goma Gateway supports **Redis-based distributed rate limiting and caching**, enabling scalable deployments across multiple instances or nodes.

By connecting to a shared Redis backend, the Gateway synchronizes request throttling and cache states, ensuring consistent behavior in **high-availability** and **load-balanced** environments.

This makes Goma Gateway well-suited for modern **cloud-native**, **containerized**, or **multi-instance** deployments.

---

### Redis Integration

To enable distributed capabilities, configure the `redis` section in your `gateway` configuration. This is **optional**, but highly recommended when running multiple Gateway instances.

---

### Example Configuration

```yaml
version: 2
gateway:
  # Redis connection for distributed rate limiting and caching
  redis:
    addr: redis:6379         # Redis server address (host:port)
    password: password       # Optional password for Redis authentication
    db: 0                    # Redis database index (default is 0)
    flushOnStartup: false  # Whether to flush Redis DB on startup (use with caution, default: false)

  timeouts:
    write: 30                # Response write timeout in seconds
    read: 30                 # Request read timeout in seconds
    idle: 30                 # Idle connection timeout in seconds
```

---

### Features Enabled by Redis

* **Distributed Rate Limiting**: Throttle requests globally across instances.
* **Shared Caching**: Cache backend responses consistently between nodes (if caching middleware is enabled).
* **High Availability**: Supports clustered and containerized deployments (e.g., Kubernetes, Docker Swarm, ECS).

---

### Notes

* If Redis is not configured, rate limiting and caching will be local to each instance.
* Redis must be reachable from all Gateway instances for consistent behavior.
* TLS or Sentinel support may be added in future versions.

---

