---
title: HTTP Caching
sidebar_label: HTTP Caching
sidebar_position: 10
---

# HTTP Caching

HTTP caching is a mechanism that stores responses associated with specific requests and reuses those stored responses for subsequent identical requests. This reduces the load on upstream servers and improves the performance of your infrastructure.

---

## HTTP Cache Middleware

Goma Gateway's **HTTP Cache Middleware** enables you to implement caching for your routes, ensuring faster response times and reduced server load. This middleware adheres to the standards outlined in **RFC 7234** (HTTP/1.1 Caching).

#### **HTTP Caching**
- **Cache Implementation**: Enable HTTP caching for routes to improve response times and reduce server load.
- **Cache Storage Options**:
  - **In-Memory Cache**: Suitable for single-instance applications or temporary caching.
  - **Redis Cache**: Ideal for distributed caching across multiple instances.
  - **Cache Control Headers**: Support for `Cache-Control`, `and X-Cache-Status` headers for fine-grained cache management.
  - **Cache Invalidation**: Implement strategies to invalidate stale cache entries (e.g., time-based or event-based invalidation).
---

## Cache Status Header

The middleware adds a `X-Cache-Status` header to responses, indicating the cache status for each request. The possible values are:

- **HIT**: The response was served directly from the cache, and the request did not reach the upstream application.
- **MISS**: The response was fetched from the upstream application and not from the cache.
- **BYPASS**: The request or response did not meet the criteria for HTTP caching, so caching was bypassed.

When the status is `BYPASS`, an `X-Goma-Cache-Reason` header says which rule
declined it — for example `the response is marked no-store` or `the request
carried credentials`. The same reason is logged at info level the first time a
route hits it, and at debug level afterwards, so a cache that never fills can be
diagnosed without reading the source. `X-Goma-Cache` carries the same status and
is not suppressed by `disableCacheStatusHeader`.

---

## Middleware Configuration Options

The HTTP Cache Middleware provides the following configuration options:

- **`maxTtl`** (`integer`, default=`300`):  
  The maximum time-to-live (in seconds) for cached responses. After this duration, cached responses expire and are invalidated.

- **`maxStale`** (`integer`, default=`0`):  
  Allows the middleware to serve stale responses if permitted by the request's `Cache-Control` directive (`max-stale`).

- **`memoryLimit`** (`string`):  
  Specifies the maximum memory allocation for the cache. Supported units include `Ki`, `Mi`, `Gi`, `Ti`, or `K`, `M`, `G`, `T` (e.g., `1Mi` for 1 megabyte).

- **`disableCacheStatusHeader`** (`boolean`):  
  When set to `true`, prevents the middleware from adding the `X-Cache-Status` header to responses.

- **`excludedResponseCodes`** (`array of strings`):  
  Configures specific HTTP response status codes or ranges of codes for which caching is disabled. For example, you can exclude error responses like `404` or `500-599`.

- **`cachePrivateResponses`** (`boolean`, default=`false`):  
  Allows responses to requests that carried credentials to be cached, keyed per caller. See [What is not cached](#what-is-not-cached) before enabling it.

- **`ignoreVary`** (`array of strings`):  
  Response `Vary` fields to disregard. Use it for a backend that advertises a
  `Vary` its bodies do not actually honour: the field is then left out of the
  cache key, so every caller shares one entry instead of each getting their own.

---

## What is not cached

The cache is shared by every caller of the route, so anything that would let one
caller read another's response stays out of it:

- **Requests carrying credentials** — an `Authorization`, `Proxy-Authorization`
  or `Cookie` header — bypass the cache in both directions. Set
  `cachePrivateResponses: true` to cache them anyway; the key then includes a
  fingerprint of those credentials, so each caller gets their own entry.
- **Responses that set a cookie**, carry `WWW-Authenticate`, or are marked
  `Cache-Control: private`, `no-store` or `no-cache`. `no-cache` is refused
  rather than stored-and-revalidated because this cache has no
  conditional-request path, so a stored copy could never be served.
- **Responses with `Vary: *`**, or varying on more than three headers — past
  that, the same resource would occupy an unreasonable number of entries.

## Responses that vary

A response with a `Vary` header is stored under a secondary key built from the
request's values for the fields it names, which is what RFC 9111 asks a cache to
do. Two callers who differ on those fields get their own entry; callers who agree
share one. The `Vary` is replayed on the cached response so caches downstream key
on it too.

Three kinds of field never reach the key:

- `Accept-Encoding` — already part of the base key.
- `Authorization`, `Proxy-Authorization` and `Cookie` — a credentialed request
  never reads a shared entry in the first place, and under
  `cachePrivateResponses` the key already includes a fingerprint of them. A
  `Vary` naming them tells the cache nothing it has not already enforced. This
  matters in practice: `raw.githubusercontent.com`, for one, answers
  `Vary: Authorization, Accept-Encoding` on public files that are identical for
  everyone.
- Anything listed in `ignoreVary`.

## Cache key

The cache key is the route name, host, negotiated encoding, path, and — when
enabled — the query parameters and the caller fingerprint, plus the secondary
key described above when the response varies. Responses to credentialed requests
are returned with `Cache-Control: private` so caches between Goma and the browser
do not store them either.

An unsafe method (`POST`, `PUT`, `DELETE`) invalidates the entry for the base
key and the one the same caller would have read. Entries stored for other
callers' `Vary` values are left to expire — they cannot be enumerated from a
single request.

---

## Example Configuration

Below is an example configuration for the HTTP Cache Middleware in YAML format:

```yaml
middlewares:
  - name: httpCache
    type: httpCache
    paths:
      - ^/store/items/(.*)$
      - /store/categories/.*
      - /api/stores/(.*)/items/(.*)
    rule:
      maxTtl: 60
      memoryLimit: 500Mi  # Supported units: Ki, Mi, Gi, Ti or K, M, G, T
      disableCacheStatusHeader: true
      cacheableStatusCodes: [200, 203, 204, 300, 301, 302, 404]
      excludedResponseCodes: [] # e.g., [500, 404]
      includeQueryInKey: false # Whether to include query parameters in the cache key
      queryParamsToCache: [] # List of specific query parameters to include in the cache key
      ignoreVary: [] # Response Vary fields to leave out of the cache key
```
---

## Notes

- **Paths**: The `paths` field supports regex patterns for flexible route matching. 

For example:
   - `^/store/items/(.*)$` matches paths starting with `/store/items/`.
   - `/store/categories/.*` matches all paths under `/store/categories/`.
   - `/api/stores/(.*)/items/(.*)` matches dynamic paths under `/api/stores/`.

###  Cache only specific query params

- **Query Parameters**: You can choose to include or exclude query parameters in the cache key. Use `includeQueryInKey` to enable or disable this feature, and `queryParamsToCache` to specify which query parameters should be considered for caching.

```yaml
middlewares:
  - name: httpCache
    type: httpCache
    paths:
      - /v1/items
    rule:
      maxTtl: 300
      memoryLimit: 500Mi  # Supported units: Ki, Mi, Gi, Ti or K, M, G, T
      disableCacheStatusHeader: true
      cacheableStatusCodes: [200]
      excludedResponseCodes: [] # e.g., [500, 404]
      includeQueryInKey: true # Whether to include query parameters in the cache key
      queryParamsToCache:
        - page
        - limit
        - category
```

In this example, the HTTP Cache Middleware is configured to cache responses for the `/v1/items` endpoint. The cache will consider only the `page`, `limit`, and `category` query parameters when determining the cache key. This allows for more granular caching based on these specific parameters, while ignoring any other query parameters that may be present in the request.

- `/v1/items?page=1&utm_source=google` => cached as `/v1/items?page=1`
- `/v1/items?page=2&session_id=xyz` => cached as `/v1/items?page=2`
- `/v1/items?category=electronics&page=1` → cached as `/v1/items?category=electronics&page=1`