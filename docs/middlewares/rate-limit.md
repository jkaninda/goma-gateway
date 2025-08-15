---
title: Rate Limiting
layout: default
parent: Middlewares
nav_order: 7
---


# RateLimit Middleware

The RateLimit middleware protects your services by controlling the rate of incoming requests, ensuring fair usage and preventing abuse. This middleware applies globally to entire routes, providing comprehensive protection without requiring individual path configuration.

## Basic Rate Limiting

Configure basic rate limiting to control request frequency:

```yaml
middlewares:
  - name: rate-limit
    type: rateLimit
    rule:
      unit: second
      requestsPerUnit: 60
```

### Parameters

| Parameter         | Type    | Description                                    | Options                         |
|-------------------|---------|------------------------------------------------|---------------------------------|
| `unit`            | string  | Time period for rate calculation               | `second`, `minute`, `hour`      |
| `requestsPerUnit` | integer | Maximum requests allowed per time unit         | Any positive integer            |
| `banAfter`        | integer | Number of rate limit violations before banning | Any positive integer            |
| `banDuration`     | string  | Duration of the ban                            | Time units: `ms`, `s`, `m`, `h` |

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
```

### Ban Duration Examples

- `500ms` - 500 milliseconds
- `30s` - 30 seconds
- `15m` - 15 minutes
- `2h` - 2 hours
- `1h30m` - 1 hour and 30 minutes

## How It Works

1. **Rate Tracking**: The middleware monitors request frequency per client
2. **Limit Enforcement**: Requests exceeding the configured rate are rejected with HTTP 429 (Too Many Requests)
3. **Violation Counting**: When banning is enabled, rate limit violations are tracked per client
4. **Automatic Banning**: After reaching the `banAfter` threshold, the client is temporarily banned
5. **Ban Expiry**: Banned clients regain access after the `banDuration` expires

