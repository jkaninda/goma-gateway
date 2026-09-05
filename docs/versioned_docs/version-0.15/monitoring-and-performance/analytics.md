---
title: Analytics
sidebar_label: Analytics
sidebar_position: 5
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

Analytics is configured in `goma.yml` alongside the rest of the gateway:

```yaml
version: 2
gateway:
  redis:
    addr: redis:6379          # required — Redis is the transport
    password: "${REDIS_PASSWORD}"
  analytics:
    enabled: true             # off by default
    stream: goma:analytics    # Redis stream key
    sample: 1                 # 0..1; 1 = every request
    maxLen: 1000000           # approximate stream length cap
    gatewayId: ""             # stamped on each event, for multi-gateway installs
  geoip:
    database: /etc/goma/country.mmdb   # optional; see GeoIP below
```

`geoip` sits beside `analytics` rather than inside it because three features read
the same database: the `country` field on events, the
`gateway_requests_by_country_total` metric, and the
[`geoBlock`](../middlewares/geo-block.md) middleware. It loads whether or not
analytics is enabled.

Or entirely from the environment, which is equivalent:

```bash
GOMA_ANALYTICS_ENABLED=true          # off by default
GOMA_ANALYTICS_STREAM=goma:analytics # Redis stream key
GOMA_REDIS_DB=0                      # must match the consumer's Redis DB
# Optional country enrichment (see GeoIP below):
GOMA_GEOIP_DB=/etc/goma/country.mmdb
```

### Configuration

Each setting can come from the config file or the environment. **The environment
wins**, field by field — so a container can override what the file ships with,
and an existing `GOMA_ANALYTICS_*` deployment keeps working unchanged after
adding the `analytics:` block.

| `gateway.analytics` | Environment | Default | Description |
|---|---|---|---|
| `enabled` | `GOMA_ANALYTICS_ENABLED` | `false` | Emit the event stream. |
| `stream` | `GOMA_ANALYTICS_STREAM` | `goma:analytics` | Redis stream key events are appended to. |
| `sample` | `GOMA_ANALYTICS_SAMPLE` | `1` | Sampling rate `0..1`; e.g. `0.25` records ~25% of requests. `1` = every request. |
| `maxLen` | `GOMA_ANALYTICS_MAXLEN` | `1000000` | Approximate stream length cap (`XADD MAXLEN ~`). |
| `gatewayId` | `GOMA_GATEWAY_ID` | `""` | Identifier stamped on each event (`gw`); useful with multiple gateways. |

Alongside it, at `gateway` level:

| `gateway` | Environment | Default | Description |
|---|---|---|---|
| `geoip.database` | `GOMA_GEOIP_DB` | *(well-known paths)* | Path to the GeoIP `.mmdb` for the `country` field. |
| — | `GOMA_REDIS_DB` | `0` | Redis database index (must match the consumer). |

A malformed `GOMA_ANALYTICS_SAMPLE` or `GOMA_ANALYTICS_MAXLEN` is logged and
ignored, falling back to the configured value — a typo must not silently drop
your sampling rate or uncap the stream.

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

Save a country-level `.mmdb` database at **`/etc/goma/country.mmdb`** and Goma
loads it at startup with no configuration; `geoip.database` (or `GOMA_GEOIP_DB`)
overrides the path. MaxMind, DB-IP and IP2Location all publish a suitable
database — any of them works, since all three expose a country ISO code.

An explicitly configured path is used **exactly as given**: Goma will not quietly
fall back to a well-known location, because enriching events from a database
nobody chose is worse than no country data at all.

It enriches the `country` field on events, the
`gateway_requests_by_country_total` metric, and powers the
[`geoBlock`](../middlewares/geo-block.md) middleware. Everything keeps working
without it — you just lose the country dimension.

Goma ships no database: the ones worth having carry licenses that bind whoever
uses or displays the data, which is a choice only you can make for your
deployment.
