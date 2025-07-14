---
title: Body Limit
layout: default
parent: Middlewares
nav_order: 12
---

# Body Limit Middleware

The **Body Limit Middleware** is designed to validate and restrict the size of incoming requests to ensure they do not exceed a specified limit. This helps protect backend services from being overwhelmed by excessively large payloads.

## Supported Units

The middleware supports the following units for specifying the request body size limit:

- **Binary Units (IEC)**:
    - `Ki`, `KiB` (Kibibytes)
    - `Mi`, `MiB` (Mebibytes)
    - `Gi`, `GiB` (Gibibytes)
    - `Ti`, `TiB` (Tebibytes)

- **Decimal Units (SI)**:
    - `K`, `KB` (Kilobytes)
    - `M`, `MB` (Megabytes)
    - `G`, `GB` (Gigabytes)
    - `T`, `TB` (Terabytes)

---

## Configuration Options

The Body Limit Middleware can be configured with the following option:

- **`limit` (string)**:
    - Specifies the maximum allowed size of the request body.
    - The value must include a unit suffix (e.g., `1K`, `1MiB`, `500MB`).

---

## Example Configuration

Below is an example of how to configure the Body Limit Middleware in a YAML configuration file:

```yaml
middlewares:
  - name: body-limit
    type: bodyLimit
    rule:
      limit: 1MiB
```

### Explanation:
- **`name`**: The name of the middleware instance.
- **`type`**: Specifies the middleware type (`bodyLimit` in this case).
- **`rule`**:
    - **`limit`**: Sets the maximum allowed request body size (e.g., `1MiB` for 1 Mebibyte).

---

## Use Cases

- **Protecting Backend Services**: Prevent large payloads from overwhelming your backend services.
- **Resource Management**: Ensure efficient use of server resources by limiting request sizes.
- **Security**: Mitigate risks associated with large payloads, such as denial-of-service (DoS) attacks.

