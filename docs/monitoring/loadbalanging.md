---
title: Load Balancing
layout: default
parent: Monitoring and Performance
nav_order: 3
---


# Load Balancing

Goma Gateway supports both **round-robin** and **weighted-based** load balancing algorithms to efficiently distribute incoming traffic across backend servers.

## Key Features

- **Round-Robin Algorithm**: Distributes incoming requests evenly across backend servers, ensuring balanced resource utilization.
- **Weighted Algorithm**: Distributes incoming requests based on predefined weights, allowing for prioritized traffic allocation to specific servers.
- **Health Checks**: Continuously monitors the health of backend servers to ensure only healthy servers receive traffic.
- **Scalability**: Enables seamless horizontal scaling by adding or removing backend servers without downtime.
- **Integrated Health Checks**: Automatically monitors the health of backend servers to maintain high availability.

---

## Example Configurations

### Round-Robin Based Load Balancing

Below is an example configuration for round-robin load balancing:

```yaml
version: 2
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
        healthyStatuses: [200, 404]
      ## destination: will be overridden by backends
      destination: ""
      backends:
        - endPoint: https://example.com
        - endPoint: https://example1.com
        - endPoint: https://example2.com
      cors: {}
```

### Weighted-Based Load Balancing

Below is an example configuration for weighted load balancing, where traffic is distributed based on server weights:

```yaml
version: 2  # Configuration version
gateway:
  routes:
    - path: /  # The path to match for this route
      name: example route  # A descriptive name for the route
      hosts:  # List of hostnames this route will handle
        - example.com
        - example.localhost
      rewrite: /  # Rewrite the incoming request path (if needed)
      methods: []  # HTTP methods to allow (empty means all methods are allowed)
      healthCheck:  # Health check configuration for backend servers
        path: "/"  # Endpoint to check for health
        interval: 30s  # Time interval between health checks
        timeout: 10s  # Timeout for health check requests
        healthyStatuses: [200, 404]  # HTTP status codes considered healthy
      ## destination: will be overridden by backends
      destination: ""  # Placeholder for backend destination (overridden by `backends`)
      backends:  # List of backend servers with weights for load balancing
        - endPoint: https://example.com  # Backend server URL
          weight: 5  # Weight for traffic distribution (higher weight = more traffic)
        - endPoint: https://example1.com  # Backend server URL
          weight: 2  # Weight for traffic distribution
        - endPoint: https://example2.com  # Backend server URL
          weight: 1  # Weight for traffic distribution
      cors: {}
```

---

## How It Works

- **Round-Robin Algorithm**: Requests are distributed sequentially across all available backend servers, ensuring an even distribution of traffic.
- **Weighted Algorithm**: Requests are distributed proportionally based on the weights assigned to each backend server. For example, a server with a weight of 5 will receive more traffic than a server with a weight of 2.
- **Health Checks**: The gateway periodically checks the health of backend servers by sending requests to the specified `healthCheck.path`.
- **Scalability**: You can dynamically add or remove backend servers without interrupting service, making it easy to scale your infrastructure as needed.

---

## Notes

- Ensure that the `healthCheck.path` is correctly configured to reflect a valid endpoint on your backend servers.
- The `healthyStatuses` field allows you to define which HTTP status codes are considered healthy. For example, `[200, 404]` means that both `200 OK` and `404 Not Found` responses are considered healthy.
- The `destination` field is overridden by the `backends` configuration, so it can be left empty or omitted.

