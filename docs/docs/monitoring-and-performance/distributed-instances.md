---
title: Distributed instances
sidebar_label: Distributed instances
sidebar_position: 4
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
    tls:                     # Optional: TLS is used only when all three are set
      clientCa: /path/to/ca.crt
      clientCert: /path/to/client.crt
      clientKey: /path/to/client.key
```

`addr` and `password` accept `${VAR}` environment references. The environment variables `GOMA_REDIS_ADDR`, `GOMA_REDIS_PASSWORD`, and `GOMA_REDIS_DB` take precedence over the configuration file.

---

### Features Enabled by Redis

* **Distributed Rate Limiting**: The [`rateLimit`](../middlewares/rate-limit.md) middleware throttles requests globally across instances.
* **Shared Caching**: The [`httpCache`](../middlewares/http-caching.md) middleware stores responses in Redis, shared between nodes.
* **Shared OIDC sessions**: The [`oidc`](../middlewares/oidc.md) middleware can keep sessions in Redis, so a login works on every instance.
* **Real-time visitors gauge**: `gateway_realtime_visitors_count` counts distinct visitors across all instances (see [Monitoring](./monitoring.md)).
* **Analytics**: The per-request [analytics event stream](./analytics.md) uses Redis as its transport.

---

### Notes

* If Redis is not configured, or the gateway cannot connect to it at startup, rate limiting and caching fall back to in-memory state local to each instance, and a warning is logged.
* Redis must be reachable from all Gateway instances for consistent behavior.
* Redis Sentinel and Redis Cluster are not supported; `addr` points to a single Redis endpoint.

---

