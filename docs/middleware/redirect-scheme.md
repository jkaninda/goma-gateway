---
title: RedirectScheme
layout: default
parent: Middleware
nav_order: 11
---

# RedirectScheme Middleware

The `RedirectScheme` middleware is used to redirect incoming HTTP requests to a different scheme (e.g., from `http` to `https`). 

This is particularly useful for enforcing secure connections or redirecting traffic to a specific port.

## Configuration

Below is an example configuration for the `RedirectScheme` middleware:

```yaml
middlewares:
  - name: redirectScheme
    type: redirectScheme
    rule:
      scheme: https       # The target scheme to redirect to (e.g., https).
      port: 8443          # (Optional) The target port to redirect to. If not specified, the default port for the scheme is used.
      permanent: false  # (Optional) If set to `true`, the redirect will use a 301 (permanent) status code. Default is `false` (302 temporary redirect).
```

### Parameters:

1. **`scheme`** (Required)  
   Specifies the target scheme for the redirect. Common values are `https` for secure connections or `http` for non-secure connections.

2. **`port`** (Optional)  
   Specifies the target port for the redirect. If not provided, the default port for the specified scheme will be used (e.g., `443` for `https`, `80` for `http`).

3. **`permanent`** (Optional)  
   Determines whether the redirect is permanent or temporary.
    - If set to `true`, a `301 Permanent Redirect` status code will be used.
    - If set to `false` (default), a `302 Temporary Redirect` status code will be used.

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
