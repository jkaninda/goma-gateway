---
title: Body Limit
sidebar_label: Body Limit
sidebar_position: 12
---

# Body Limit Middleware

The Body Limit Middleware validates and restricts the size of incoming HTTP request bodies to protect your services from oversized payloads that could cause performance issues or security vulnerabilities.

## Overview

When a request exceeds the configured size limit, the middleware will reject it before it reaches your backend services, returning an appropriate HTTP error response. This provides an essential layer of protection against resource exhaustion and potential denial-of-service attacks.

## Configuration

### Basic Configuration

```yaml
middlewares:
  - name: body-limit
    type: bodyLimit
    rule:
      limit: 1MiB
```

### Configuration Parameters

| Parameter | Type   | Required | Description                                        |
|-----------|--------|----------|----------------------------------------------------|
| `limit`   | string | Yes      | Maximum allowed request body size: an integer with a unit suffix, e.g. `512KB`, `10MiB` |

The unit is required and case-sensitive. An invalid `limit` is logged and the
middleware is not applied. The limit applies to every path of the route; `paths`
is ignored.

## Supported Size Units

The middleware accepts both binary (IEC) and decimal (SI) unit formats:

### Binary Units (IEC)
- `Ki`, `KiB` - Kibibytes (1,024 bytes)
- `Mi`, `MiB` - Mebibytes (1,024² bytes)
- `Gi`, `GiB` - Gibibytes (1,024³ bytes)
- `Ti`, `TiB` - Tebibytes (1,024⁴ bytes)
- `Pi`, `PiB`, `Ei`, `EiB` are also accepted

### Decimal Units (SI)
- `K`, `KB` - Kilobytes (1,000 bytes)
- `M`, `MB` - Megabytes (1,000² bytes)
- `G`, `GB` - Gigabytes (1,000³ bytes)
- `T`, `TB` - Terabytes (1,000⁴ bytes)
- `P`, `PB`, `E`, `EB` are also accepted

## Configuration Examples

### API with Small Payloads
```yaml
middlewares:
  - name: api-body-limit
    type: bodyLimit
    rule:
      limit: 512KB
```

### File Upload Service
```yaml
middlewares:
  - name: upload-body-limit
    type: bodyLimit
    rule:
      limit: 50MiB
```

### Large Data Processing
```yaml
middlewares:
  - name: bulk-data-limit
    type: bodyLimit
    rule:
      limit: 1GB
```

## Behavior

### Request Processing
1. **Under Limit**: Requests with body sizes within the limit are forwarded to the next middleware or backend service
2. **Over Limit**: Requests whose `Content-Length` exceeds the limit are rejected with HTTP 413 (Payload Too Large) before any of the body is read
3. **Unknown Length**: For bodies without a `Content-Length` (chunked uploads), reading is cut off at the limit, so no more than `limit` bytes are ever read or forwarded
4. **No Body**: Requests without a body (GET, HEAD, etc.) pass through without validation

### Error Response
When a request's declared `Content-Length` exceeds the limit, the middleware returns:
- **Status Code**: `413 Payload Too Large`
- **Response Body**: `Request body too large (limit <n> bytes)`

