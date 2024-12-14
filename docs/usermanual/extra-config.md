---
title: Extra Config
layout: default
parent: User Manual
nav_order: 3
---


## Extra Config

The **Extra Config** feature enables you to define additional routes and middlewares in separate `.yml` or `.yaml` files, stored in a specified directory.

This approach helps streamline the management of routes and middlewares, especially as configurations grow in size.

When managing many routes and middlewares in a single file, it can become cumbersome.

By using the **Extra Config** feature, you can split configurations into smaller, more manageable files, making them easier to maintain.

### Example Configuration

To define extra routes, specify the configuration in the `gateway` section as shown below:

```yaml
version: 1.0
gateway:
  ...
  ## Add additional configuration
  extraConfig:
    # Directory containing additional configuration files.
    directory: /etc/goma/extra
    watch: false  # Set to true to watch for changes in the directory.
  routes:
    - path: /
      name: example
```
### Routes Configuration

You can create additional route configurations by placing them in files with a `.yaml` or `.yml` extension inside the `/etc/goma/extra` directory. 

Here’s an example of a route configuration file:

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
    rateLimit: 60  # Requests per minute.
    disableHostForwarding: true
    blockCommonExploits: false
    middlewares:
      - auth-middleware  # List of middlewares for this route.
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
    disableHostForwarding: true
    interceptErrors: [404, 401]
    blockCommonExploits: false
    middlewares:
      - auth-middleware  # List of middlewares for this route.
```
### Extra Middlewares

Similarly to routes, you can define middlewares in separate files stored in the `/etc/goma/extra` directory. 
These middlewares can be applied globally or to specific routes.

```yaml
##### Extra Middlewares
middlewares:
  # Basic Authentication middleware.
  - name: extra-basic-auth
    type: basic  # Authentication type (options: basic, jwt, OAuth).
    paths:
      - /user
      - /admin
      - /account
    rule:
      username: admin
      password: admin

  # Access control middleware to block specific paths.
  - name: extra-api-forbidden-paths
    type: access
    paths:  # Paths to block.
      - /swagger-ui/*
      - /v2/swagger-ui/*
      - /api-docs/*
      - /internal/*
      - /actuator/*
```


