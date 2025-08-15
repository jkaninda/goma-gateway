---
title: Body Limit
layout: default
parent: Middlewares
nav_order: 12
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
| `limit`   | string | Yes      | Maximum allowed request body size with unit suffix |

## Supported Size Units

The middleware accepts both binary (IEC) and decimal (SI) unit formats:

### Binary Units (IEC)
- `Ki`, `KiB` - Kibibytes (1,024 bytes)
- `Mi`, `MiB` - Mebibytes (1,024² bytes)
- `Gi`, `GiB` - Gibibytes (1,024³ bytes)
- `Ti`, `TiB` - Tebibytes (1,024⁴ bytes)

### Decimal Units (SI)
- `K`, `KB` - Kilobytes (1,000 bytes)
- `M`, `MB` - Megabytes (1,000² bytes)
- `G`, `GB` - Gigabytes (1,000³ bytes)
- `T`, `TB` - Terabytes (1,000⁴ bytes)

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
2. **Over Limit**: Requests exceeding the limit are immediately rejected with an HTTP 413 (Payload Too Large) status code
3. **No Body**: Requests without a body (GET, HEAD, etc.) pass through without validation

### Error Response
When a request exceeds the configured limit, the middleware returns:
- **Status Code**: `413 Payload Too Large`
- **Response Body**: Error message indicating the size limit was exceeded

