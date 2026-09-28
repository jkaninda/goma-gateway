---
title: RedirectScheme
sidebar_label: RedirectScheme
sidebar_position: 11
---

# RedirectScheme Middleware

The `redirectScheme` middleware redirects requests to a different scheme (e.g., from `http` to `https`), keeping the host, path and query string.

This is particularly useful for enforcing secure connections or redirecting traffic to a specific port.

## Configuration

Below is an example configuration for the `RedirectScheme` middleware:

```yaml
middlewares:
  - name: redirectScheme
    type: redirectScheme
    rule:
      scheme: https       # The target scheme to redirect to (e.g., https).
      port: 8443          # (Optional) The target port to redirect to. If not specified, the request's port (if any) is kept.
      permanent: false  # (Optional) If set to `true`, the redirect will use a 301 (permanent) status code. Default is `false` (302 temporary redirect).
```

### Parameters:

1. **`scheme`** (Required)  
   Specifies the target scheme for the redirect. Common values are `https` for secure connections or `http` for non-secure connections.

2. **`port`** (Optional)  
   Specifies the target port for the redirect. It replaces any port in the
   request's host, and is omitted from the URL when it is the scheme's default
   (`443` for `https`, `80` for `http`). If not provided, the request's host is
   used unchanged, including any port it carries.

3. **`permanent`** (Optional)  
   Determines whether the redirect is permanent or temporary.
    - If set to `true`, a `301 Moved Permanently` status code will be used.
    - If set to `false` (default), a `302 Found` status code will be used.

### Behavior

- Requests already on the target scheme pass through. Behind a load balancer,
  the scheme is read from `X-Forwarded-Proto` only when the request comes from a
  trusted proxy (see [Running behind a proxy](../usermanual/running-behind-a-proxy.md)).
- Requests under `/.well-known/acme-challenge/` are never redirected.
- When the route has `hosts`, a request `Host` that is not one of them is
  replaced by the route's first host in the redirect, so a client cannot steer
  the `Location` header.
- `paths` is ignored; every request on the route is redirected.

## Example Use Cases

1. **Enforcing HTTPS**  
   Redirect all HTTP traffic to HTTPS to ensure secure communication:

```yaml
   middlewares:
     - name: enforceHttps
       type: redirectScheme
       rule:
         scheme: https
```

2. **Custom Port Redirection**  
   Redirect HTTP traffic to HTTPS on a custom port (e.g., `8443`):

```yaml
   middlewares:
     - name: redirectToCustomPort
       type: redirectScheme
       rule:
         scheme: https
         port: 8443
```

3. **Permanent Redirect**  
   Permanently redirect HTTP traffic to HTTPS:

```yaml
   middlewares:
     - name: permanentHttpsRedirect
       type: redirectScheme
       rule:
         scheme: https
         permanent: true
```
