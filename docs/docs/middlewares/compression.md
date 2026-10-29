---
title: Compression
sidebar_label: Compression
sidebar_position: 11
---

# Compression

The `compress` middleware compresses responses with **zstd**, **Brotli** or **gzip**, chosen per request from the client's `Accept-Encoding` header. Text payloads such as JSON, HTML, CSS, JavaScript and SVG typically shrink to 10–30% of their size.

It always runs **innermost**, right around the proxy, whatever its position in the route's `middlewares` list. Combined with [HTTP Caching](http-caching.md), the cache stores the compressed body, so a cache hit costs no compression at all.

---

## Quick start

```yaml
middlewares:
  - name: compression
    type: compress
```

That is all most routes need. Attach it to a route, or to every route through `defaults`:

```yaml
gateway:
  defaults:
    middlewares: [compression]
  routes:
    - name: api
      path: /
      target: http://api:8080
      middlewares: [compression]
```

---

## Configuration

```yaml
middlewares:
  - name: compression
    type: compress
    paths: ["/api/*", "/static/*"]    # optional; default: the whole route
    rule:
      algorithms: [zstd, br, gzip]    # server preference
      minSize: 1KiB                   # bytes (1024) or with a unit (1KiB, 2KB)
      levels:
        gzip: 5                       # 1-9
        br: 2                         # 1-11
        zstd: default                 # fastest | default | better | best
      includedContentTypes: []        # empty = built-in list (below)
      excludedContentTypes: ["application/pdf"]
      excludedPaths: ["/login", "/account/*"]
      upstream: passthrough           # passthrough | identity
```

| Key                    | Type       | Default             | Description |
|------------------------|------------|---------------------|-------------|
| `algorithms`           | `[]string` | `[zstd, br, gzip]`  | Codings offered, in server preference order. A tie in the client's q-values goes to the earlier entry. |
| `minSize`              | size       | `1KiB`              | Bodies smaller than this are sent uncompressed. |
| `levels.gzip`          | `int`      | `5`                 | gzip level, 1 (fastest) to 9 (smallest). |
| `levels.br`            | `int`      | `2`                 | Brotli level, 1 to 11. |
| `levels.zstd`          | `string`   | `default`           | `fastest`, `default`, `better` or `best`. |
| `includedContentTypes` | `[]string` | built-in list       | Media types to compress. Replaces the built-in list. |
| `excludedContentTypes` | `[]string` | `[]`                | Media types never compressed. |
| `excludedPaths`        | `[]string` | `[]`                | Paths never compressed. Same [patterns](overview.md#path-patterns) as `paths`. |
| `upstream`             | `string`   | `passthrough`       | `passthrough` forwards the client's `Accept-Encoding` and keeps a backend-compressed body as it is. `identity` asks the backend for an uncompressed body, so backends spend no CPU on compression and the gateway picks the coding. |

Content-type patterns accept an exact type (`application/json`), a wildcard subtype (`text/*`) or a structured-syntax suffix (`application/*+json`).

**Built-in compressible types:** `text/*`, `application/json`, `application/*+json`, `application/x-ndjson`, `application/javascript`, `application/x-javascript`, `application/ecmascript`, `application/xml`, `application/*+xml`, `application/yaml`, `application/x-yaml`, `application/toml`, `application/graphql`, `application/wasm`, `application/x-www-form-urlencoded`, `application/vnd.ms-fontobject`, `application/x-font-ttf`, `font/ttf`, `font/otf`, `image/svg+xml`, `image/x-icon`, `image/vnd.microsoft.icon`, `image/bmp`.

---

## What is never compressed

A response is sent exactly as the backend produced it when any of these hold:

- the client sent no `Accept-Encoding`, or accepts none of the configured codings;
- the request is `HEAD`, carries a `Range` header, or is a WebSocket / protocol upgrade;
- the status is 1xx, 204, 206 or 304;
- the response already has a `Content-Encoding`, or `Cache-Control: no-transform`;
- the media type is not compressible, or is excluded;
- the body is smaller than `minSize`;
- the path matches `excludedPaths`.

Server-Sent Events (`text/event-stream`) and gRPC (`application/grpc*`) are never compressed, whatever the configuration says.

---

## Headers

On a compressed response the middleware:

- sets `Content-Encoding` to the chosen coding, and `X-Goma-Compression` to the same value, so you can tell the gateway compressed the response rather than the backend;
- adds `Vary: Accept-Encoding` (also on uncompressed responses of a compressible type, so shared caches keep the variants apart);
- removes `Content-Length` and `Accept-Ranges`;
- turns a strong `ETag` into a weak one (`"abc"` → `W/"abc"`), since the encoded bytes differ from the body the backend's validator describes.

When the client revalidates with `If-None-Match: W/"abc"`, the gateway forwards `"abc"`, so the backend still answers `304 Not Modified`.

---

## Streaming

Responses that the backend flushes as it goes (NDJSON, long polling, token streams) are compressed and flushed chunk by chunk: each flush delivers a complete, decodable block to the client without waiting for the end of the body.

---

## With HTTP caching

Because compression runs inside the cache, the cache stores the compressed body. Entries are keyed by the **set** of codings the client accepts, so header order and q-values do not fragment the cache, and a client is never replayed a coding it cannot decode. Expect up to one stored copy per distinct set of accepted codings; browsers send only a few distinct sets in practice. Size `memoryLimit` accordingly.

```yaml
middlewares:
  - name: cache
    type: httpCache
    paths: ["/*"]
    rule:
      maxTtl: 60
  - name: compression
    type: compress
```

---

## Choosing algorithms and levels

zstd gives the best speed for its ratio and is supported by current Chrome, Edge and Firefox. Safari does not send `zstd`, so it is served Brotli when `br` is offered. Brotli in the gateway is pure Go: the default level 2 is close to zstd's ratio, while level 4 encodes about four times slower than zstd for little gain. If gateway CPU is the constraint, lower `levels.br` to `1`, or drop `br` from `algorithms` so Safari falls back to gzip. The Brotli window is capped at 512 KiB, so each in-flight response holds 1–3 MiB of encoder state.

Measured on a 2 vCPU Xeon @ 2.8 GHz, 64 KiB JSON body, middleware alone:

| Coding        | Throughput | Output / input |
|---------------|-----------:|---------------:|
| gzip level 5  | 188 MB/s   | 0.142          |
| zstd default  | 246 MB/s   | 0.131          |
| br level 4    | 44 MB/s    | 0.128          |
| br level 1    | 143 MB/s   | 0.130          |

Benchmark your own payloads with:

```bash
GOMA_BENCH_FILE=/path/to/response.json \
  go test ./internal/middlewares -run '^$' -bench BenchmarkCompressFile -benchmem
```

---

## Security: BREACH

Compressing a page that reflects attacker-controlled input next to a secret (a CSRF token, a session-bound value) lets an attacker who can observe response sizes recover the secret over many requests. Exclude such pages with `excludedPaths`, or mask secrets per request. JSON APIs authenticated by headers are generally not exposed.

---

## Metrics

With `monitoring.enableMetrics: true`:

| Metric | Labels | Description |
|--------|--------|-------------|
| `gateway_compression_bytes_in_total`  | `name`, `encoding` | Body bytes handed to the compressor. |
| `gateway_compression_bytes_out_total` | `name`, `encoding` | Compressed bytes sent. |
| `gateway_compression_skipped_total`   | `name`, `reason`   | Responses sent uncompressed: `client_identity`, `content_type`, `too_small`, `already_encoded`, `no_transform`, `status`, `method`, `range`, `excluded_path`, `upgrade`. |

Compression ratio per route:

```promql
sum by (name) (rate(gateway_compression_bytes_out_total[5m]))
  / sum by (name) (rate(gateway_compression_bytes_in_total[5m]))
```

`gateway_response_bytes_total` keeps counting the bytes actually sent to clients, so it drops when compression is enabled.
