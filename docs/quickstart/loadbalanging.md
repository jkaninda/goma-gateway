---
title: Load Balancing
layout: default
parent: Quickstart
nav_order: 4
---


# Load Balancing

Goma Gateway supports rund robim load blancing

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
            interval: 0
            timeout: 0
            healthyStatuses: [200,404]
          ## destination: will be override by backends
          destination: ""
          backends:
            - https://example.com
            - https://example2.com
            - https://example4.com
          cors:
```

