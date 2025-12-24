---
title: Extra Config
layout: default
parent: User Manual
nav_order: 3
---


##  Extra Config

The **Extra Config** feature enables you to modularize your API Gateway configuration by placing additional route and middleware definitions in separate `.yaml` or `.yml` files. This approach improves maintainability, especially in large deployments where managing everything in a single file can become unwieldy.


### How It Works

* Define the `extraConfig` block in your main `gateway` configuration.
* Use the `directory` field to specify the location where your additional configuration files are stored.
* Files with `.yaml` or `.yml` extensions within that directory will be automatically loaded at startup.
* Goma supports recursive loading of configuration files from subdirectories, allowing for better organization of complex configurations.
* If the `watch` option is enabled:
    * The Gateway will monitor the top level `extraConfig.directory` for file changes and automatically reload modified configurations.
    * **Note:** Recursive live watching is **not** supported, only files directly within the specified directory are monitored for changes.


### Benefits

* **Separation of Concerns:** Keep related routes and middlewares grouped in isolated files.
* **Scalability:** Easily scale configurations for large applications or teams.
* **Hot Reloading:** Update configurations on the fly without restarting the Gateway (when `watch` is enabled).

---

### Example: Gateway Extra Config Block

```yaml
version: 2
gateway:
  ...
  extraConfig:
    directory: /etc/goma/extra  # Directory with extra YAML files
    watch: false                # Set to true to enable live reloading
  routes:
    - path: /
      name: example
```

---

## Defining Additional Routes

You can split routes into individual or grouped files placed under the directory specified by `extraConfig.directory`. These files must use the `routes:` key at the root level.

### Example: `/etc/goma/extra/routes.yaml`

```yaml
routes:
  - path: /order
    name: order-service
    rewrite: /
    methods: [GET, PUT]
    backends:
      - endpoint: https://api.example.com
      - endpoint: https://api2.example.com
      - endpoint: https://api3.example.com
    healthCheck:
      path: /
      interval: 30s
      timeout: 10s
      healthyStatuses: [200, 404]
    middlewares:
      - auth-middleware

  - path: /cart
    name: cart-service
    methods: [GET, PUT, POST]
    target: http://cart-service:8080
    healthCheck:
      path: /
      interval: 30s
      timeout: 10s
      healthyStatuses: [200, 404]
    cors:
      origins: []
      headers: {} 
    middlewares:
      - auth-middleware
```

---

## Defining Additional Middlewares

You can also define middlewares in separate files placed in the same directory. These middlewares can be referenced globally or per route.

### Example: `/etc/goma/extra/middlewares.yaml`

```yaml
middlewares:
  # Basic Authentication middleware
  - name: extra-basic-auth
    type: basicAuth
    paths:
      - /user
      - /admin/*
      - /account
    rule:
      realm: your-realm
      users:
        - admin:{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc=
        - admin:$2a$12$LaPhf23UoCGepWqDO0IUPOttStnndA5V8w7XPNeP0vn712N5Uyali
        - admin:admin

  # Access control middleware to block sensitive paths
  - name: extra-api-forbidden-paths
    type: access
    paths:
      - /swagger-ui/*
      - /v2/swagger-ui/*
      - /api-docs/*
      - /internal/*
      - /actuator/*
```

---

## Best Practices

* Use descriptive filenames (e.g. `routes-cart.yaml`, `middlewares-auth.yaml`) to organize large sets of configuration files.
