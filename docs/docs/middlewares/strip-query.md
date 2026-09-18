---
title: Strip Query
sidebar_label: Strip Query
sidebar_position: 10
---

# Strip Query Middleware

The **Strip Query** middleware removes named query parameters from a request
before it is forwarded upstream.

Use it for an *optional* hint the backend would honour but that the gateway
should not pass on. Dropping the parameter lets the request succeed, where
refusing it outright would fail an otherwise valid call.

## Quick Start

```yaml
middlewares:
  - name: strip-debug-params
    type: stripQuery
    paths: ["/.*"]
    rule:
      params: ["debug", "trace"]
```

A request for `/api/orders?id=42&debug=true` is forwarded as
`/api/orders?id=42`.

## Configuration

| Parameter     | Type       | Required | Description                                                                       |
|---------------|------------|----------|-----------------------------------------------------------------------------------|
| `params`      | `[]string` | **Yes**  | Query parameter names to remove.                                                  |
| `methods`     | `[]string` | No       | Restrict the rule to these HTTP methods (case-insensitive). Empty applies to all. |
| `pathPattern` | `string`   | No       | Restrict the rule to request paths matching this regular expression.              |

### `params`

At least one parameter name is required. A middleware configured with an empty
`params` list is **not applied**, and the gateway logs an error at startup:

```
Error middleware not applied: stripQuery requires at least one param
```

Parameter names are matched exactly. A parameter that is not present on the
request is ignored.

### `methods`

Limits stripping to specific HTTP methods. Values are compared
case-insensitively, so `get` and `GET` are equivalent.

```yaml
rule:
  params: ["preview"]
  methods: ["GET", "HEAD"]
```

### `pathPattern`

Limits stripping to request paths matching a Go regular expression.

```yaml
rule:
  params: ["debug"]
  pathPattern: "^/api/v1/.*"
```

:::warning

An invalid regular expression **disables the rule** rather than widening it —
the middleware is not applied at all, and the gateway logs:

```
Error middleware not applied: invalid stripQuery pathPattern
```

Check your startup logs after changing `pathPattern`.

:::

## Example: dropping a tracing parameter

Strip an internal tracing flag from public traffic so it can never reach the
backend, while leaving every other parameter untouched:

```yaml
middlewares:
  - name: strip-internal-flags
    type: stripQuery
    paths: ["/.*"]
    rule:
      params: ["x-internal-trace", "x-debug-user"]
      pathPattern: "^/public/.*"

routes:
  - name: public-api
    path: /public
    target: http://api:8080
    middlewares:
      - strip-internal-flags
```

## Behavior notes

- Stripping happens **before** the request is forwarded, so the upstream never
  sees the parameter.
- A request that carries none of the configured parameters is passed through
  **completely untouched** — the query string is not rewritten.
- When at least one parameter *is* removed, the remaining query string is
  re-encoded, which sorts the parameters alphabetically by name. Backends that
  depend on the original parameter order (for example, when computing a
  signature over the raw query string) will see the reordered form.
- Both `URL.RawQuery` and `RequestURI` are updated, so the removed parameter
  cannot reappear on the outbound request.
