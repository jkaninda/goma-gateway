---
title: Access Log Middleware
layout: default
parent: Middlewares
nav_order: 18
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
- name: custom-logger
  type: accessLog
  paths:
    - "/.*"
  rule:
    headers:
      - CF-IPCountry
    query:
      - debug
      - source
    cookies:
      - session_id
```

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
    - auth_token
```

Logs selected cookies for traceability or session analysis.

---

## Path-Based Logging

You can limit logging enrichment to specific paths:

```yaml
paths:
  - /api/*
  - /admin/*
```

This helps reduce log noise and control sensitive data exposure.

---

## Log Output Behavior

* Missing fields are logged as empty or null values
* Values are captured **at request time**
* Fields are appended to existing access log entries
* The logging format depends on your gateway’s global log configuration

---

## Example: Observability-Focused Logging

```yaml
- name: observability-logger
  type: accessLog
  paths:
    - /api/*
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

