---
title: Analytics
layout: default
parent: Monitoring and Performance
nav_order: 5
---

## Analytics (event stream)

Beyond Prometheus counters, Goma Gateway can emit a **per-request analytics event
stream** to Redis. Where `/metrics` gives you aggregate numbers, the stream
carries one compact, privacy-safe event per request — enough to build full
**HTTP traffic, performance and web-analytics** dashboards downstream.

[Miabi](https://github.com/miabi-io/miabi) consumes this stream to power its
**Workspace Analytics** (traffic by country, latency percentiles, unique
visitors, top pages, …). You can also consume it yourself with any Redis Streams
client.

### How it works

- On each proxied request Goma builds a small `AnalyticsEvent` and appends it to a
  **Redis Stream** (default `goma:analytics`) with a batched, pipelined `XADD`.
- Delivery is **non-blocking**: it never adds latency to the request path — a full
  in-memory buffer drops the event rather than waiting. An approximate `MAXLEN`
  cap bounds the stream so a lagging consumer can't grow Redis unbounded.
- Requires Redis to be configured (the transport). It reuses the same Redis the
  gateway already uses for caching / distributed rate limiting.

> ⚠️ **Same Redis, same database.** The consumer must read from the exact Redis
> **and database index** Goma writes to. If nothing appears downstream, check that
> `GOMA_REDIS_DB` matches the consumer's Redis DB — a mismatch silently breaks the
> pipeline.

### Privacy

The stream is designed to carry **no PII**:

- The client **IP never leaves the gateway**. It is used only to (a) derive a
  **daily-salted visitor hash** (`vid`) for counting unique visitors and (b) look
  up a **country** via GeoIP — then it is dropped.
- No cookies are set or required.

### Enabling it

```bash
GOMA_ANALYTICS_ENABLED=true          # off by default
GOMA_ANALYTICS_STREAM=goma:analytics # Redis stream key
GOMA_REDIS_DB=0                      # must match the consumer's Redis DB
# Optional country enrichment (see GeoIP below):
GOMA_GEOIP_DB=/etc/goma/GeoLite2-Country.mmdb
```

### Configuration (environment)

| Variable | Default | Description |
|---|---|---|
| `GOMA_ANALYTICS_ENABLED` | `false` | Set to `true` to emit the event stream. |
| `GOMA_ANALYTICS_STREAM` | `goma:analytics` | Redis stream key events are appended to. |
| `GOMA_ANALYTICS_SAMPLE` | `1` | Sampling rate `0..1`; e.g. `0.25` records ~25% of requests. `1` = every request. |
| `GOMA_ANALYTICS_MAXLEN` | `1000000` | Approximate stream length cap (`XADD MAXLEN ~`). |
| `GOMA_GATEWAY_ID` | `""` | Identifier stamped on each event (`gw`); useful with multiple gateways. |
| `GOMA_REDIS_DB` | `0` | Redis database index (must match the consumer). |
| `GOMA_GEOIP_DB` | `/etc/goma/GeoLite2-Country.mmdb` | Path to the GeoIP `.mmdb` for the `country` field. |

### Event schema

Each stream entry has a single field `e` whose value is the JSON below.

| Field | Type | Description |
|---|---|---|
| `ts` | int | Event time, unix milliseconds. |
| `gw` | string | Gateway id (`GOMA_GATEWAY_ID`). |
| `name` | string | Matched route name. |
| `host` | string | Request `Host`. |
| `method` | string | HTTP method. |
| `status` | int | Response status code. |
| `path` | string | Request path. |
| `path_template` | string | Matched route path pattern. |
| `req_bytes` | int | Request body bytes received. |
| `resp_bytes` | int | Response body bytes sent. |
| `duration_ms` | int | Total request duration. |
| `upstream_ms` | int | Upstream/backend duration (overhead = `duration_ms − upstream_ms`). |
| `vid` | string | Daily-salted visitor hash (**not** the IP). |
| `country` | string | ISO country code from GeoIP (empty when no database). |
| `ua` | string | Raw `User-Agent` (parsed into browser/OS/device downstream). |
| `referer_host` | string | Host of the `Referer`, if any. |

### GeoIP (country enrichment)

Set `GOMA_GEOIP_DB` to a MaxMind-format `.mmdb` (both MaxMind
`GeoLite2-Country.mmdb` and IP2Location `IP2LOCATION-*.MMDB` work — both expose a
country ISO code). It enriches the `country` field on events, the
`gateway_requests_by_country_total` metric, and powers the
[`geoBlock`](../middlewares/geo-block.md) middleware. Everything keeps working
without it — you just lose the country dimension.
