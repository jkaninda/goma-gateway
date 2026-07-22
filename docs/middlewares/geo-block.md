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

The middleware requires a country-level GeoIP database in MaxMind `.mmdb` format. MaxMind, DB-IP and IP2Location all publish one — any of them works, since all three expose a `country.iso_code`.

Save it as **`/etc/goma/country.mmdb`** and Goma picks it up with no configuration. To keep it elsewhere, set `GOMA_GEOIP_DB`:

```bash
GOMA_GEOIP_DB=/srv/geoip/dbip-country-lite.mmdb
```

An explicit `GOMA_GEOIP_DB` is used exactly as given — Goma will not quietly fall back to another file, because geo rules deciding on a database nobody chose is worse than geo rules that do not run.

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

`addCountryHeader` is applied to every allowed request, so any rule can double as
country enrichment. Use a `DENY` blocklist with a country you don't expect to see
(so nothing is actually blocked) purely to attach the header:

```yaml
middlewares:
  - name: geo-header
    type: geoBlock
    rule:
      action: DENY
      countries: [ZZ]        # not a real country ⇒ blocks nothing
      addCountryHeader: X-Country-Code
```

> The backend then reads `X-Country-Code` on every request without shipping its own GeoIP database.

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
