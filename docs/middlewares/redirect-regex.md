---
title: RedirectRegex
layout: default
parent: Middlewares
nav_order: 13
---

# Redirect Middleware

The `RedirectRegex` middleware is used to redirect incoming HTTP requests to a different hostname using regular expressions.
This is particularly useful for enforcing domain changes or redirecting traffic to specific hostnames based on patterns.
## Configuration

Below is an example configuration for the `RedirectRegex` middleware:

```yaml
middlewares:
  - name: redirect-regex
    type: redirectRegex
    rule:
      pattern: ^/oldpath/(.*)
      replacement: https://newdomain.com/newpath/$1
      permanent: false  # (Optional) If set to `true`, the redirect will use a 301 (permanent) status code. Default is `false` (302 temporary redirect).
```
