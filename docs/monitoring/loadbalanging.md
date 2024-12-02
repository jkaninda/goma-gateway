---
title: Load Balancing
layout: default
parent: Monitoring and Performance
nav_order: 3
---


# Load Balancing

Goma Gateway supports round-robin algorithm load balancing.

It comes with an integrated load balancing backends healthcheck.

```yaml
version: 1.0
gateway:
    routes:
        - path: /
          name: example route
          hosts:
            - example.com
            - example.localhost
          rewrite: /
          methods: []
          healthCheck:
            path: "/"
            interval: 30s
            timeout: 10s
            healthyStatuses: [200,404]
          ## destination: will be override by backends
          destination: ""
          backends:
            - https://example.com
            - https://example2.com
            - https://example4.com
          cors:
```

