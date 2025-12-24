---
title: HTTP Caching
layout: default
parent: Middlewares
nav_order: 10
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

---

## Example Configuration

Below is an example configuration for the HTTP Cache Middleware in YAML format:

```yaml
middlewares:
  - name: httpCache
    type: httpCache
    paths:
      - ^/store/items/(.*)$
      - /store/categories/*
      - /api/stores/(.*)/items/(.*)
    rule:
      maxTtl: 60
      memoryLimit: 500Mi  # Supported units: Ki, Mi, Gi, Ti or K, M, G, T
      disableCacheStatusHeader: true
      cacheableStatusCodes: [200, 203, 204, 300, 301, 302, 404]
      excludedResponseCodes: [] # e.g., [500, 404]
      includeQueryInKey: false # Whether to include query parameters in the cache key
      queryParamsToCache: [] # List of specific query parameters to include in the cache key
```
---

## Notes

- **Paths**: The `paths` field supports regex patterns for flexible route matching. 

For example:
   - `^/store/items/(.*)$` matches paths starting with `/store/items/`.
   - `/store/categories/*` matches all paths under `/store/categories/`.
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