---
title: Redirect
layout: default
parent: Middlewares
nav_order: 12
---

# Redirect Middleware

The `Redirect` middleware is used to redirect incoming HTTP requests to a different hostname.

This is particularly useful for enforcing domain changes or redirecting traffic to a specific hostname.

## Configuration

Below is an example configuration for the `Redirect` middleware:

```yaml
middlewares:
  - name: redirect-host
    type: redirect
    rule:
      url: https://newdomain.com   # The target URL to redirect to.
      permanent: false  # (Optional) If set to `true`, the redirect will use a 301 (permanent) status code. Default is `false` (302 temporary redirect).
```

### Parameters:

1. **`url`** (Required)  
   Specifies the target URL for the redirect. This should include the scheme (e.g., `http`, `https`) and the hostname.

2**`permanent`** (Optional)  
   Determines whether the redirect is permanent or temporary.
    - If set to `true`, a `301 Permanent Redirect` status code will be used.
    - If set to `false` (default), a `302 Temporary Redirect` status code will be used.

## Example Use Cases

1. **Enforcing Domain Change**  
   Redirect all traffic from an old domain to a new domain:
   
```yaml
   middlewares:
     - name: redirectToNewDomain
       type: redirect
       rule:
         url: https://newdomain.com
         permanent: true
```