---
title: Monitoring and Performance
sidebar_label: Monitoring and Performance
sidebar_position: 7
---

## Monitoring and Performance

Goma Gateway exposes what it is doing through metrics, health endpoints, logs, and an optional per-request event stream.

- [Monitoring](./monitoring.md) — Prometheus metrics, the `/healthz`, `/readyz` and `/healthz/routes` endpoints, and the Grafana dashboard.
- [Logging](./logging.md) — log levels, text and JSON formats, file output and rotation.
- [Analytics](./analytics.md) — the per-request event stream published to Redis, and GeoIP country enrichment.
- [Distributed Instances](./distributed-instances.md) — sharing rate limits, caches and visitor counts across instances through Redis.
