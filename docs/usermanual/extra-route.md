---
title: Extra Routes
layout: default
parent: User Manual
nav_order: 3
---


## Extra Routes

The Extra Routes feature allows you to define additional routes by using .yml or .yaml files stored in a specified directory.

This approach helps you avoid the complexity of managing all routes in a single file.

When dealing with many routes, maintaining them in one file can quickly become unwieldy. With this feature, you can organize your routes into separate files, making them easier to manage and maintain.

Example of an extra route

Defined an extra route path in `gateway` section as shown below.

```yaml
version: 1.0
gateway:
  ...
  ## Add additional routes
  extraRoutes:
    # path
    directory: /etc/goma/extra
    watch: false
  routes:
    - path: /
      name: example
```
## Routes Configuration
Below is an example of configuring routes for the Gateway, defining service paths, methods, backends, health checks, and other settings.

Create a file in `/etc/goma/extra` using `yaml` or `.yaml` extension.

```yaml
 routes:
     - path: /order
       name: order-service
       hosts: []
       rewrite: /
       methods:
         - GET
         - PUT
       backends:
         - http://order-service:8080
         - http://order-service2:8080
         - http://order-service3:8080
       healthCheck:
         path: /
         interval: 30s
         timeout: 10s
         healthyStatuses:
          - 200
          - 404
       cors:
         origins: []
         headers: {}
       rateLimit: 60
       disableHostFording: true
       interceptErrors: [404,401]
       blockCommonExploits: false
       middlewares:
         - auth-middleware
     - path: /cart
       name: cart-service
       hosts: []
       rewrite: /
       methods:
         - GET
         - PUT
         - POST
       destination: http://cart-service:8080
       healthCheck:
         path: /
         interval: 30s
         timeout: 10s
         healthyStatuses:
           - 200
           - 404
       cors:
         origins: []
         headers: {}
       rateLimit: 60
       disableHostFording: true
       interceptErrors: [404,401]
       blockCommonExploits: false
       ## List of middleware
       middlewares:
         - auth-middleware

```

## Extra Middlewares

Create a file in `/etc/goma/extra` using `yaml` or `.yaml` extension.

```yaml
##### Extra Middlewares
middlewares:
  # Enable Basic auth authorization based
  - name: extra-basic-auth
    # Authentication types | jwt, basic, OAuth
    type: basic
    paths:
      - /user
      - /admin
      - /account
    rule:
      username: admin
      password: admin
  # The server will return 403
  - name: extra-api-forbidden-paths
    type: access
    ## prevents access paths
    paths:
      - /swagger-ui/*
      - /v2/swagger-ui/*
      - /api-docs/*
      - /internal/*
      - /actuator/*
```