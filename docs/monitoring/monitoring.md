---
title: Monitoring
layout: default
parent: Monitoring and Performance
nav_order: 1
---


# Monitoring

Goma Gateway collects and exports metrics to help monitor the system’s performance.

## Enable Metrics

To enable metrics collection, set the `enableMetrics` field to `true` in the configuration file. Metrics will be available at the `/metrics` endpoint.

### Example Configuration:

```yaml
version: 1.0
gateway:
  enableMetrics: true
  ...
```
Once enabled, metrics can be scraped and visualized using monitoring tools like Prometheus and Grafana.

For additional configuration and examples, visit the Goma Gateway Documentation.
