---
title: RedirectRegex
sidebar_label: RedirectRegex
sidebar_position: 13
---

# RedirectRegex Middleware

The `redirectRegex` middleware redirects requests whose URL matches a regular
expression, building the target from the match. Use it to move paths or to
change domain while keeping the request path.

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

A request to `/oldpath/a/b?x=1` is redirected to
`https://newdomain.com/newpath/a/b?x=1`.

### Parameters

| Parameter     | Type    | Required | Description                                                                  |
|---------------|---------|----------|------------------------------------------------------------------------------|
| `pattern`     | string  | Yes      | Go regular expression matched against the request path plus query string (`/path?query`) |
| `replacement` | string  | Yes      | Target URL. `$1`, `$2`, ... refer to capture groups                          |
| `permanent`   | boolean | No       | `301 Moved Permanently` when `true`, `302 Found` otherwise (default)         |

Because the query string is part of the matched input, a pattern ending in
`(.*)` carries it over to the target. Requests that do not match, and requests
under `/.well-known/acme-challenge/`, are passed through unchanged. `paths` is
ignored; the pattern alone selects which requests are redirected.
