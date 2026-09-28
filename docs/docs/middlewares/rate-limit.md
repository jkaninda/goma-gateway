---
title: Rate Limiting
sidebar_label: Rate Limiting
sidebar_position: 7
---


# RateLimit Middleware

The RateLimit middleware protects your services by controlling the rate of incoming requests, ensuring fair usage and preventing abuse. Without `paths` it applies to every path of the route; with `paths`, only matching requests are counted and limited (see [Path patterns](overview.md#path-patterns)).

Limits are kept in memory per gateway instance. When Redis is configured on the
gateway (`gateway.redis`), limits and bans are stored in Redis and shared by all
instances. If Redis becomes unreachable, requests are allowed rather than
rejected.

## Basic Rate Limiting

Configure basic rate limiting to control request frequency:

```yaml
middlewares:
  - name: rate-limit
    type: rateLimit
    rule:
      unit: minute
      requestsPerUnit: 60
      burst: 100
```

### Parameters

| Parameter         | Type    | Default    | Description                                                                 |
|-------------------|---------|------------|-----------------------------------------------------------------------------|
| `requestsPerUnit` | integer | required   | Requests allowed per `unit`. The middleware is not applied without it       |
| `unit`            | string  | `second`   | `second`, `minute` or `hour`                                                |
| `burst`           | integer | `0`        | Extra requests allowed in a burst; bucket capacity is `requestsPerUnit + burst` |
| `banAfter`        | integer | `0` (off)  | Number of rate limit violations (429 responses) before the client is banned |
| `banDuration`     | string  | `10m`      | Duration of the ban, e.g. `500ms`, `30s`, `15m`, `1h30m`                    |
| `keyStrategy`     | object  | client IP  | Strategy to identify clients for rate limiting. See below                   |

### Key Strategy
The `keyStrategy` defines how clients are identified for rate limiting. You can choose from the following strategies:

| Strategy Type    | Description                                     | Additional Parameters             |
|------------------|-------------------------------------------------|-----------------------------------|
| `source: ip`     | Uses the client's IP address for identification | None                              |
| `source: header` | Uses a specific HTTP header for identification  | `name`: Name of the header to use |
| `source: cookie` | Uses a specific cookie for identification       | `name`: Name of the cookie to use |

When the header or cookie is missing from a request, or `name` is empty, the
client IP is used instead.

> **`header` and `cookie` keys are chosen by the caller.** A client that changes
> the value gets a fresh allowance, so these strategies only limit anything when
> the value has already been verified by a middleware in front of the rate
> limiter — a JWT-derived header, or a session cookie the gateway issued. On an
> unauthenticated route, use `source: ip`.
>
> Goma caps how many distinct keys it tracks and drops idle ones, so an endless
> supply of made-up keys cannot exhaust memory; it will log when that cap is
> reached, which usually means the strategy is being applied to a value the
> caller controls.

### Example Scenarios

**High-frequency API (1 request per second):**

```yaml
rule:
  unit: second
  requestsPerUnit: 1
```

**Standard API (100 requests per minute):**

```yaml
rule:
  unit: minute
  requestsPerUnit: 100
```

**Bulk operations (1000 requests per hour):**

```yaml
rule:
  unit: hour
  requestsPerUnit: 1000
```

## Advanced Rate Limiting with Automatic Banning

For enhanced protection against persistent abuse, enable automatic banning of clients that repeatedly exceed rate limits:

```yaml
middlewares:
  - name: rate-limit-with-ban
    type: rateLimit
    rule:
      unit: minute
      requestsPerUnit: 100
      banAfter: 5
      banDuration: 30m
      keyStrategy:
        source: header
        name: Authorization
```

### Ban Duration Examples

- `500ms` - 500 milliseconds
- `30s` - 30 seconds
- `15m` - 15 minutes
- `2h` - 2 hours
- `1h30m` - 1 hour and 30 minutes

## How It Works

1. **Rate Tracking**: The middleware monitors request frequency per client
2. **Limit Enforcement**: Requests exceeding the configured rate are rejected with HTTP 429 (Too Many Requests). Tokens refill continuously at `requestsPerUnit` per `unit`
3. **Violation Counting**: When banning is enabled, rate limit violations are tracked per client
4. **Automatic Banning**: After reaching the `banAfter` threshold, the client is temporarily banned and receives HTTP 403 (Forbidden)
5. **Ban Expiry**: Banned clients regain access after the `banDuration` expires

