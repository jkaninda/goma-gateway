---
title: Monitoring
layout: default
parent: Monitoring and Performance
nav_order: 1
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

