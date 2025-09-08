---
title: Maintenance Mode
layout: default
parent: User Manual
nav_order: 10
---

# Maintenance Mode

Goma Gateway provides a **maintenance mode** feature that allows you to temporarily block access to your backend services. This is useful during:

* Planned maintenance windows
* Service upgrades or deployments
* Emergency downtime or troubleshooting

When enabled, Goma Gateway responds to all incoming requests with a configurable HTTP status code and message, instead of forwarding the request to your backend.

---

## Configuration Fields

* **`enabled`** (`boolean`, required)
  Whether maintenance mode is active.

    * `true` → Maintenance mode enabled (all requests blocked).
    * `false` → Maintenance mode disabled (requests routed normally).

* **`statusCode`** (`integer`, optional, default: `503`)
  The HTTP status code returned when maintenance mode is active.

    * Common values:

        * `503` → Service Unavailable (default)
        * `500` → Internal Server Error
        * `404` → Not Found (useful if you want the service to appear absent)

* **`message`** (`string`, optional)
  The response body to send when maintenance mode is active.

    * Defaults to: `"Service temporarily unavailable"`.
    * Can be returned in **plain text**, **JSON**, or **XML**, depending on your needs.

---

## Example: Maintenance Mode Configuration

```yaml
routes:
  - name: api-example
    path: /
    target: http://api-example:8080
    maintenance:
      enabled: true
      statusCode: 503
      message: "503 Service Unavailable"
```




