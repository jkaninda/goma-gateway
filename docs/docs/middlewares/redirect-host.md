---
title: RedirectHost
sidebar_label: RedirectHost
sidebar_position: 12
---

# RedirectHost Middleware

The `redirectHost` middleware redirects a request to another host, keeping the
scheme, path and query string. Use it to make one hostname canonical: add or
remove the `www.` prefix, or send every alias of a site to its main domain.

## Configuration

Add `www.` to every host the route serves (`example.com` → `www.example.com`):

```yaml
middlewares:
  - name: add-www
    type: redirectHost
    rule:
      www: add
      permanent: true
```

Remove it (`www.example.com` → `example.com`):

```yaml
middlewares:
  - name: remove-www
    type: redirectHost
    rule:
      www: remove
      permanent: true
```

Send every other host to one canonical host (`old-brand.com/pricing` →
`example.com/pricing`):

```yaml
middlewares:
  - name: canonical-host
    type: redirectHost
    rule:
      host: example.com
      permanent: true
```

### Parameters

| Parameter   | Type    | Required        | Description                                                                 |
|-------------|---------|-----------------|-----------------------------------------------------------------------------|
| `www`       | string  | One of the two  | `add` or `remove` the `www.` prefix of the request host                     |
| `host`      | string  | One of the two  | Fixed target host, optionally with a port (`example.com`, `example.com:8443`) |
| `permanent` | boolean | No              | `301 Moved Permanently` when `true`, `302 Found` otherwise (default)        |

Set either `www` or `host`, not both.

### Behaviour

- A request already on the target host is passed through, so attaching
  `www: add` to a route serving both `example.com` and `www.example.com` never
  loops.
- With `www`, the request's port is kept. With `host`, the port is the one
  written in `host`, if any.
- When the route lists `hosts`, only those hosts are redirected; any other
  `Host` header is passed through, so a client cannot choose the redirect
  target.
- IP addresses and requests under `/.well-known/acme-challenge/` are passed
  through unchanged, so certificates for both names can still be issued.
- The route must serve both names, and each needs a certificate, for the
  redirect to be reached over HTTPS.
