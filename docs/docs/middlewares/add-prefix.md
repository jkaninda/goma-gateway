---
title: AddPrefix
sidebar_label: AddPrefix
sidebar_position: 8
---


# AddPrefix Middleware

The `addPrefix` middleware adds a prefix to the beginning of the URL path of incoming requests. This is useful for routing requests to services that require a specific prefix in their paths.

## How It Works
- **Request Interception**: The AddPrefix middleware intercepts incoming requests.
- **Prefix Addition**: It adds the configured prefix to the beginning of the URL path.
- **Forwarding**: The modified request is forwarded to the appropriate service or backend.
## Configuration Properties
- **`prefix`** (`string`): The prefix to be added to the URL path. Start it with `/` and end it with `/`: the prefix and the request path are joined as-is, so `/prefix` would turn `/api/resource` into `/prefixapi/resource`.

The prefix applies to every request on the route; `paths` is ignored.

## Example

```yaml
middlewares:
  - name: add-prefix
    type: addPrefix
    rule:
      prefix: /prefix/
```
In this example:

- The middleware adds `/prefix` to the beginning of every incoming URL path.
- For instance, a request to `/api/resource` would be transformed into `/prefix/api/resource`

## When to Use AddPrefix
- To ensure requests have a consistent prefix before reaching the backend services.
- To manage routing for services with path-based prefixes.

For more complex path changes, use the [RewriteRegex middleware](rewrite-regex.md).