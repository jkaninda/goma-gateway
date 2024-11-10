---
title: Monitoring
layout: default
parent: Quickstart
nav_order: 6
---


# Monitoring

Goma collects and exports metrics

To enable metrics, you need to set `enableMetrics` to `true` and the metrics are available at `/metrics`

```yaml
version: 1.0
gateway:
  enableMetrics: true
  ...
```

