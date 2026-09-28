---
title: Access Log
sidebar_label: Access Log
sidebar_position: 18
---

# Access Log Middleware

The **Access Log Middleware** (`accessLog`) enables you to enrich access logs with **custom request attributes** such as headers, query parameters, cookies, and other contextual data. This helps improve observability, traceability, and debugging across your services.

---

## Overview

By default, access logs typically contain basic information such as request method, path, status code, and response time. The `accessLog` middleware allows you to **extend those logs** with additional request-level data that is critical for:

* Debugging production issues
* Tracking client behavior
* Correlating requests across systems
* Enhancing security and audit logging
* Improving monitoring and analytics

---

## Basic Configuration

```yaml
middlewares:
  - name: custom-logger
    type: accessLog
    rule:
      headers:
        - CF-IPCountry
      query:
        - debug
        - source
      cookies:
        - session_id
```

At least one of `headers`, `query` or `cookies` must be set; otherwise the
middleware is not applied.

This configuration logs:

* The `CF-IPCountry` request header (useful for geo-location)
* The `debug` and `source` query parameters
* The `session_id` cookie value

---

## Supported Log Fields

The middleware can extract values from multiple parts of the incoming request.

### Headers

```yaml
rule:
  headers:
    - X-Request-ID
    - User-Agent
```

Logs the specified HTTP request headers.

---

### Query Parameters

```yaml
rule:
  query:
    - page
    - limit
```

Logs values from the request query string.

---

### Cookies

```yaml
rule:
  cookies:
    - session_id
```

Logs selected cookies for traceability or session analysis.

---

## Scope

The enrichment applies to every request on the routes the middleware is
attached to; `paths` is ignored. To enrich only some requests, attach the
middleware to a dedicated route.

:::caution
Logged values are written in clear text. Avoid logging credentials or session
tokens (`Authorization`, session cookies) unless your log pipeline is trusted to
hold them.
:::

---

## Log Output Behavior

* Fields that are absent from the request are omitted from the log entry
* Header fields are logged under their lowercased name (e.g. `cf-ipcountry`); query parameters and cookies under the name as configured
* Fields are appended to the route's existing access log entry
* The logging format depends on your gateway's global log configuration

---

## Example: Observability-Focused Logging

```yaml
middlewares:
  - name: observability-logger
    type: accessLog
    rule:
      headers:
        - X-Request-ID
        - User-Agent
        - CF-IPCountry
      query:
        - version
      cookies:
        - session_id
```

