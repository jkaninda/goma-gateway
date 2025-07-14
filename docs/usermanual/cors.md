---
title: Cross-Origin Resource Sharing (CORS)
layout: default
parent: User Manual
nav_order: 4
---


## Cross-Origin Resource Sharing (CORS)

CORS (Cross-Origin Resource Sharing) defines how your API can be accessed by web applications from different origins (domains). It ensures secure cross-origin requests and data transfers between browsers and servers.

In **Goma Gateway**, CORS can be configured at two levels:

* **Global CORS**: Applies to all routes by default.
* **Route-Specific CORS**: Overrides global settings for individual routes.

These settings help control which external domains can communicate with your backend and under what conditions.

---

### Configuration Fields

Each CORS configuration supports the following fields:

* **`origins`** (`[]string`): List of allowed origin URLs.
* **`allowedHeaders`** (`[]string`): Headers allowed in requests.
* **`headers`** (`map[string]string`): Additional headers to include in responses.
* **`exposeHeaders`** (`[]string`): Headers that browsers can access from the response.
* **`maxAge`** (`int`): Number of seconds the results of a preflight request can be cached.
* **`allowMethods`** (`[]string`): List of allowed HTTP methods (e.g., `GET`, `POST`). If empty, all methods are allowed.
* **`allowCredentials`** (`boolean`): Whether credentials (cookies, authorization headers) are allowed in requests.

---

### Example: Global CORS Configuration

```yaml
version: 2
gateway:
  cors:
    origins:
      - http://localhost:3000
      - https://dev.example.com
    allowedHeaders:
      - Origin
      - Authorization
      - X-Client-Id
      - Content-Type
      - Accept
    headers:
      X-Session-Id: xxx-xxx-xx
      Access-Control-Max-Age: 1728000
    exposeHeaders: []
    maxAge: 1728000
    allowMethods: ["GET", "POST"]
    allowCredentials: true
```

> This configuration enables requests from two specific origins and permits certain headers and methods globally.

---

### Example: Route-Specific CORS Configuration

```yaml
version: 2
gateway:
  routes:
    - name: example
      path: /
      rewrite: /
      target: https://api.example.com
      disableHostForwarding: false
      blockCommonExploits: true
      cors:
        origins:
          - http://localhost:3000
          - https://dev.example.com
        allowedHeaders:
          - Origin
          - Authorization
          - X-Client-Id
          - Content-Type
          - Accept
        headers:
          X-Session-Id: xxx-xxx-xx
          Access-Control-Max-Age: 1728000
        exposeHeaders: []
        maxAge: 1728000
        allowMethods: ["GET", "POST"]
        allowCredentials: true
```

> This route-specific CORS configuration allows fine-grained control, overriding the global CORS settings for just this route.

---