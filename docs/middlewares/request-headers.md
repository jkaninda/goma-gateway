---
title: Request Headers
layout: default
parent: Middlewares
nav_order: 15
---

# Request Headers Middleware

The **Request Headers Middleware** (`requestHeaders`) lets you **add, override, or remove HTTP request headers** before they are forwarded to the upstream backend. It is commonly used to inject identification headers, strip sensitive client headers, or normalize requests across heterogeneous backends.

---

## Overview

The `requestHeaders` middleware intercepts inbound requests on a route and applies a set of header rules. Typical uses include:

* Inject identification or trace headers (`X-Forwarded-Proto`, `X-Tenant-ID`, `X-Request-Source`).
* Strip sensitive client headers before they reach the backend (`Authorization`, `Cookie`).
* Normalize headers required by legacy backends.
* Override values that clients should not control.

Header rules are applied in this order:

1. `removeHeaders` — drop the listed headers.
2. `setHeaders` — set or override. An empty value (`""`) deletes the header.

Because `setHeaders` runs after `removeHeaders`, you can re-introduce a header with a fresh value in a single rule.

---

## Basic Configuration

```yaml
middlewares:
  - name: inject-proto
    type: requestHeaders
    rule:
      setHeaders:
        X-Forwarded-Proto: "https"
```

### Configuration Parameters

| Parameter       | Type                | Required | Description                                                                                                                            |
|-----------------|---------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------|
| `setHeaders`    | map<string,string>  | No       | Headers to set or override on the outgoing request. Empty string (`""`) deletes a client-supplied header.                              |
| `removeHeaders` | list<string>        | No       | Header names to drop before forwarding. Applied **before** `setHeaders`.                                                               |

At least one of `setHeaders` or `removeHeaders` must be set; otherwise the middleware is a no-op and is not attached.

### Path Scoping

Like other middlewares, an optional `paths` list scopes the rule to specific URL patterns within a route. When omitted, the rule applies to all requests on the route.

```yaml
middlewares:
  - name: api-only
    type: requestHeaders
    paths: [/api/*]
    rule:
      setHeaders:
        X-API-Surface: "public"
```

Path patterns support exact match, `/*` wildcard, and regex (same syntax as other middlewares).

---

## Examples

### Inject a Tenant ID and Force a Scheme

```yaml
middlewares:
  - name: tenant-headers
    type: requestHeaders
    rule:
      setHeaders:
        X-Tenant-ID: "acme"
        X-Forwarded-Proto: "https"
```

### Strip Client Credentials

```yaml
middlewares:
  - name: drop-auth
    type: requestHeaders
    rule:
      removeHeaders:
        - Authorization
        - Cookie
```

### Override a Client-Supplied Header

`setHeaders` always wins over an incoming value:

```yaml
middlewares:
  - name: pin-content-type
    type: requestHeaders
    rule:
      setHeaders:
        Content-Type: "application/json"
```

### Delete a Specific Header via `setHeaders`

Empty values in `setHeaders` delete a header. Useful when the same rule both removes and adds:

```yaml
middlewares:
  - name: rotate-trace
    type: requestHeaders
    rule:
      setHeaders:
        X-Legacy-Trace: ""             # delete client value
        X-Trace-ID: "${REQUEST_ID}"    # add fresh value
```

### Path-Scoped Rules

```yaml
middlewares:
  - name: admin-headers
    type: requestHeaders
    paths:
      - /admin/*
    rule:
      setHeaders:
        X-Admin-Surface: "true"
      removeHeaders:
        - X-User-Public-Token
```

---

## Behavior

### Application Order

1. **`removeHeaders`** runs first and drops every listed header from the inbound request.
2. **`setHeaders`** runs second. Each entry sets the header (overriding any existing value) or deletes it when the value is the empty string.

This ordering means `removeHeaders: [X]` followed by `setHeaders: { X: "fresh" }` results in `X: fresh` reaching the backend, regardless of what the client sent.

### Header Normalization

Header names are case-insensitive on the wire. Goma uses Go's `http.Header` semantics, which canonicalize names (e.g., `x-tenant-id` becomes `X-Tenant-Id`).

### Interaction With Other Middlewares

| Middleware         | Order Relative to `requestHeaders`                                              |
|--------------------|---------------------------------------------------------------------------------|
| `bodyLimit`        | Runs first; oversized requests are rejected before headers are mutated.         |
| `forwardAuth`      | Sees the request **after** `requestHeaders` is applied.                         |
| `rewriteRegex`     | Path rewrite runs after `requestHeaders`.                                       |
| `responseHeaders`  | Independent; operates on the response, not the request.                         |

When multiple `requestHeaders` rules are attached to the same route, they apply in the order listed.
