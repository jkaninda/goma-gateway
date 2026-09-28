---
title: RewriteRegex
sidebar_label: RewriteRegex
sidebar_position: 9
---


# RewriteRegex Middleware

The `rewriteRegex` middleware rewrites the URL path of requests using regular expressions before they are forwarded. Unlike a redirect, the client is not told: the backend simply receives the new path. It is ideal for rewrite rules that the route's `rewrite` property cannot express.

## How It Works
- **Pattern Matching**: The request path (without the query string) is matched against the Go regular expression `pattern`.
- **Rewrite Action**: Every match is replaced with `replacement`. A path that does not match is left unchanged.
- **Scope**: The rule applies to every request on the route; `paths` is ignored. An invalid `pattern` is logged and requests pass through unchanged.

## Example

```yaml
middlewares:
  - name: rewrite-oldpath-to-newpath
    type: rewriteRegex
    rule:
      pattern: ^/oldpath/(.*)
      replacement: /newpath/$1
```

In this example:

- The middleware matches URLs starting with `/oldpath/` followed by any characters `(.*)`.
- The matched portion after `/oldpath/` is captured and referenced in the replacement as `$1`.
- The resulting path is rewritten to `/newpath/{captured_segment}`.

## Dynamic tokens

In addition to regex capture groups (`$1`, `$2`, …), the `replacement` may reference
values from the incoming request using `{{goma.<source>.<name>}}` placeholders:

| Token                          | Resolves to                                   |
|--------------------------------|-----------------------------------------------|
| `{{goma.headers.<HeaderName>}}` | The value of the given request header.        |
| `{{goma.query.<ParamName>}}`    | The value of the given URL query parameter.   |

Notes:

- Whitespace inside the braces is tolerated, e.g. `{{ goma.query.workspace }}`.
- A missing header or query parameter resolves to an empty string.
- Token values are URL-path-escaped, so each token always expands to a **single
  path segment**. A client-supplied value such as `../../admin` cannot inject
  extra `/` separators or traverse the path — it becomes `..%2F..%2Fadmin`.
- Tokens are expanded **after** the regex replacement, so a header or query value
  containing `$1` is never treated as a capture-group reference.

```yaml
middlewares:
  - name: rewrite-with-tokens
    type: rewriteRegex
    rule:
      pattern: ^/v2/[^/]+/(.*)
      # Header value routes the request; query param selects the environment.
      replacement: /v2/{{goma.headers.X-Workspace-Id}}/{{goma.query.env}}/$1
```

For a request `POST /v2/acme/frontend/blobs?env=prod` with header
`X-Workspace-Id: ws_1`, the path is rewritten to `/v2/ws_1/prod/frontend/blobs`.

## When to Use RewriteRegex

- When simple rewrites (like those handled by the `rewrite` property) are not enough.
- When you need to handle dynamic path segments or complex patterns.

For straightforward rewrites, consider using the route `rewrite` property instead to reduce complexity.