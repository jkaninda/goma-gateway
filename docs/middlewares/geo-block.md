---
title: Geo Block
layout: default
parent: Middlewares
nav_order: 19
---

# Geo Block Middleware

The Geo Block middleware provides country-based access control for routes, allowing or denying requests based on the client's country resolved from a GeoIP database. It applies globally to the route, so there is no need to configure path-level restrictions.

## Overview

The `geoBlock` middleware resolves the client's country from its IP address (using the configured GeoIP database) and enforces a policy:

- **ALLOW**: only the listed countries may access the route (allowlist).
- **DENY**: the listed countries are blocked; everyone else is allowed (blocklist).

It can also enrich the upstream request with the resolved country header, so your backend can localize content, prices, or behavior without shipping its own GeoIP database.

Privacy note: the client IP is used only to look up the country at the edge and is never forwarded — only the ISO country code is.

## Prerequisites

The middleware requires a GeoIP database in MaxMind `.mmdb` format. Both MaxMind (`GeoLite2-Country.mmdb`) and IP2Location (`IP2LOCATION-*.MMDB`) are supported — both expose a `country.iso_code`.

Set the path with the `GOMA_GEOIP_DB` environment variable (default `/etc/goma/GeoLite2-Country.mmdb`):

```bash
GOMA_GEOIP_DB=/etc/goma/GeoLite2-Country.mmdb
```

If the database is absent or unreadable, country resolution is disabled and the middleware follows its `allowUnknown` setting (fail-open by default), so a missing database never locks everyone out.

## Configuration

### Basic Structure

```yaml
middlewares:
  - name: <middleware-name>
    type: geoBlock
    rule:
      action: <ALLOW|DENY>
      countries:
        - <ISO-3166-1-alpha-2>
```

### Parameters

| Parameter               | Type    | Required | Default | Description                                                                                                   |
|-------------------------|---------|----------|---------|---------------------------------------------------------------------------------------------------------------|
| `action`                | String  | Yes      | —       | Policy action. `ALLOW` (allowlist) or `DENY` (blocklist).                                                      |
| `countries`             | Array   | Yes      | —       | List of ISO 3166-1 alpha-2 country codes (e.g. `US`, `FR`, `DE`).                                              |
| `statusCode`            | Integer | No       | `403`   | HTTP status returned for a blocked request.                                                                    |
| `message`               | String  | No       | `Access denied from your region` | Response body message for a blocked request.                                        |
| `allowUnknown`          | Boolean | No       | `true`  | What to do when the country can't be resolved (no database, private IP, lookup miss). `true` allows (fail-open); `false` blocks (fail-closed). |
| `addCountryHeader`      | String  | No       | —       | When set, the resolved country is added to the upstream request under this header (e.g. `X-Country-Code`).     |

### Behavior

- **Country codes** are ISO 3166-1 alpha-2 and matched case-insensitively.
- **Private and loopback clients bypass** the check — internal, mesh, and health-check traffic (loopback, RFC 1918 private, link-local) is never geo-fenced.
- **Unresolved country** follows `allowUnknown`. The default is fail-open, so an absent or unreadable database can't block legitimate traffic.
- **`addCountryHeader`** is applied to allowed requests too, making the middleware usable purely for enrichment (combine with a permissive rule).

## Configuration Examples

### Example 1: Allowlist (only these countries)

```yaml
middlewares:
  - name: eu-only
    type: geoBlock
    rule:
      action: ALLOW
      countries:
        - FR
        - DE
        - ES
        - IT
      message: "This service is only available in the EU."
```

### Example 2: Blocklist (deny specific countries)

```yaml
middlewares:
  - name: sanctions-block
    type: geoBlock
    rule:
      action: DENY
      countries:
        - KP
        - IR
      statusCode: 451   # Unavailable For Legal Reasons
```

### Example 3: Fail-closed (deny anything un-geolocated)

```yaml
middlewares:
  - name: strict-us-only
    type: geoBlock
    rule:
      action: ALLOW
      countries: [US]
      allowUnknown: false   # unresolved country is blocked
```

### Example 4: Country enrichment for the upstream

```yaml
middlewares:
  - name: geo-header
    type: geoBlock
    rule:
      action: DENY
      countries: []          # blocks nothing
      addCountryHeader: X-Country-Code
```

> To enrich without blocking, use a `DENY` action with an empty (or non-matching) country list; every request passes and carries the `X-Country-Code` header upstream.

## Applying the Middleware

Reference the middleware by name on a route:

```yaml
routes:
  - name: my-app
    path: /
    hosts:
      - app.example.com
    backends:
      - endpoint: http://backend:8080
    middlewares:
      - eu-only
```

Order matters: place `geoBlock` before authentication and rate-limiting middlewares so blocked regions are rejected as early as possible.

## Metrics

Denied requests are counted by the Prometheus metric:

```
gateway_geoblock_denied_total{name="<middleware-name>", country="<ISO code>"}
```

Combined with `gateway_requests_by_country_total`, this lets you monitor how much traffic each rule rejects and from where.
