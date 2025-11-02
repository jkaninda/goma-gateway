---
title: Running behind a Proxy
layout: default
parent: User Manual
nav_order: 11
---


# Running Behind a Proxy or CDN

When deploying **Goma Gateway** behind a reverse proxy or Content Delivery Network (CDN) — such as **Nginx**, **Traefik**, **Cloudflare**, or **AWS CloudFront** — special configuration is required to ensure correct client IP detection and reliable request logging.

By default, Goma only sees the proxy’s IP address. The proxy configuration allows Goma to extract the **real client IP** from trusted proxy headers, ensuring that features like rate limiting, access policy, and audit logs work as intended.

---

## Proxy Configuration

The `proxy` configuration block helps Goma Gateway accurately determine the originating client IP address when operating behind trusted proxy layers.

When enabled, Goma inspects specific headers (such as `X-Forwarded-For`) **only** if the incoming request originates from a trusted proxy IP or CIDR block.

---

### Available Options

| Key              | Type       | Default                            | Description                                                                      |
|------------------|------------|------------------------------------|----------------------------------------------------------------------------------|
| `enabled`        | `bool`     | `false`                            | Enables proxy mode. Set to `true` if Goma runs behind a reverse proxy or CDN.    |
| `trustedProxies` | `[]string` | `[]`                               | List of trusted proxy IP addresses or CIDR ranges allowed to forward client IPs. |
| `ipHeaders`      | `[]string` | `["X-Forwarded-For", "X-Real-IP"]` | Ordered list of HTTP headers to check for the original client IP.                |

---

### Example Configuration

```yaml
gateway:
  proxy:
    enabled: true                     # Enable proxy mode if Goma runs behind a proxy or CDN
    trustedProxies:                   # List of trusted proxy IPs or CIDRs (IPv4 and IPv6)
      - "127.0.0.1"
      - "10.0.0.0/8"
      - "192.168.0.0/16"
      - "::1"                         
      - "fc00::/7"
    ipHeaders:                        # Headers checked (in order) to determine the real client IP
      - "CF-Connecting-IP"
      - "X-Forwarded-For"
      - "X-Real-IP"
      - "True-Client-IP"
      - "Forwarded"
```

---

### Notes

* Only requests coming **from trusted proxies** are allowed to override the client IP.
* If `enabled` is `false`, Goma will **ignore all forwarding headers** and use the request’s direct remote address.
* Misconfiguring `trustedProxies` may lead to spoofed IPs or inaccurate client identification. Always include only **known and controlled proxy networks**.



