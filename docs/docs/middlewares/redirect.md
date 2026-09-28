---
title: Redirect
sidebar_label: Redirect
sidebar_position: 12
---

# Redirect Middleware

The `redirect` middleware redirects every request on a route to a fixed URL.

This is particularly useful for enforcing domain changes or retiring a route.

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

### Parameters

1. **`url`** (Required)  
   The target URL. An absolute URL (with scheme and host) is used exactly as
   written: the request's path and query string are **not** appended. A relative
   URL (e.g. `/maintenance`) keeps the request's query string.

2. **`permanent`** (Optional)  
   Determines whether the redirect is permanent or temporary.
    - If set to `true`, a `301 Moved Permanently` status code will be used.
    - If set to `false` (default), a `302 Found` status code will be used.

Requests under `/.well-known/acme-challenge/` are never redirected, so ACME
certificate validation keeps working. The redirect applies to every other path
of the route; `paths` is ignored. To keep the request path while changing
domain, use [RedirectRegex](redirect-regex.md).

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