---
title: Running behind a Proxy
sidebar_label: Running behind a Proxy
sidebar_position: 11
---


# Running Goma Gateway Behind a Proxy or CDN

When deploying **Goma Gateway** behind a reverse proxy or Content Delivery Network (CDN) — such as **Nginx**, **Cloudflare**, or **AWS CloudFront** — special configuration is required to ensure correct client IP detection and reliable request logging.

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
| `trustedProxies` | `[]string` | `[]`                               | **Required when `enabled` is `true`.** Proxy IP addresses or CIDR ranges allowed to forward client IPs. An empty list means no proxy is trusted, so every forwarded header is ignored. |
| `ipHeaders`      | `[]string` | `["X-Forwarded-For", "X-Real-IP"]` | Ordered list of HTTP headers to check for the original client IP.                |

---

### Example Configuration

> Minimal Example

```yaml
gateway:
  proxy:
    enabled: true
    trustedProxies:
      - "10.0.0.0/8"                  # the proxy in front of Goma — required
    # Default headers X-Forwarded-For and X-Real-IP will be used
    # ipHeaders: ["CF-Connecting-IP"]
```

>  Full Example

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

### Behind Cloudflare

Cloudflare connects to your origin from its own network, so those ranges are
what `trustedProxies` has to contain. Cloudflare publishes them, and they do
change — take them from the source rather than copying a list out of a blog
post:

* IPv4 — [https://www.cloudflare.com/ips-v4](https://www.cloudflare.com/ips-v4)
* IPv6 — [https://www.cloudflare.com/ips-v6](https://www.cloudflare.com/ips-v6)
* Both, as JSON — [https://api.cloudflare.com/client/v4/ips](https://api.cloudflare.com/client/v4/ips)
* Reference — [Cloudflare IP Ranges](https://www.cloudflare.com/ips/)

```yaml
gateway:
  proxy:
    enabled: true
    trustedProxies:
      # From https://www.cloudflare.com/ips-v4 — abridged; use the full list.
      - "173.245.48.0/20"
      - "103.21.244.0/22"
      - "104.16.0.0/13"
      - "131.0.72.0/22"
      # From https://www.cloudflare.com/ips-v6
      - "2400:cb00::/32"
      - "2606:4700::/32"
      - "2803:f800::/32"
    ipHeaders:
      - "CF-Connecting-IP"            # Cloudflare sets this on every request
      - "X-Forwarded-For"
```

`CF-Connecting-IP` is only worth trusting because of the list above. Cloudflare
overwrites that header on every request it proxies, so it cannot be forged — but
only for connections that genuinely came from Cloudflare. If Goma accepted it
from any source, a caller could set it directly and choose their own IP, which
is why an empty `trustedProxies` disables the feature rather than trusting
everyone.

Keep the list current. Cloudflare announces changes on its
[IP ranges page](https://www.cloudflare.com/ips/); a range added after you
copied the list will simply stop being trusted, and requests through it fall
back to the connecting address.

> Origins reachable only through Cloudflare should also be firewalled to those
> ranges. Otherwise anyone who learns the origin address can bypass Cloudflare
> altogether, and no header configuration will help.

---

### Notes

* Only requests coming **from trusted proxies** are allowed to override the client IP.
* If `enabled` is `false`, Goma will **ignore all forwarding headers** and use the request’s direct remote address.
* **`trustedProxies` must not be empty.** An empty list with `enabled: true` is rejected at startup and all forwarding headers are ignored, because there would be nothing to distinguish a proxy from a client that simply sends the header itself.
* The client IP is taken from the **rightmost** entry of the chain that is not one of your own proxies. The leftmost entry is whatever the original caller wrote there, so it is never trusted.
* `X-Forwarded-Proto` and `X-Forwarded-Scheme` follow the same rule. Read from an untrusted source they would let a caller declare a plaintext request to be TLS, which turns off the HTTPS redirect and the `Secure` flag on session cookies.

> **Behind a TLS-terminating load balancer, this section is required.** Without
> it Goma sees the plaintext hop between the balancer and itself, so a
> `redirectScheme` middleware will keep redirecting to HTTPS and session cookies
> will not be marked `Secure`.

* Misconfiguring `trustedProxies` may lead to spoofed IPs or inaccurate client identification. Always include only **known and controlled proxy networks**.



