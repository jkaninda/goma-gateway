---
title: AddPrefix
layout: default
parent: Middleware
nav_order: 8
---


### AddPrefix middleware

The `AddPrefix` middleware appends a specified prefix to the URL path of incoming requests. This is useful for routing requests to services that require a specific prefix in their paths
## How It Works:
- **Request Interception**: The AddPrefix middleware intercepts incoming requests.
- **Prefix Addition**: It adds the configured prefix to the beginning of the URL path.
- **Forwarding**: The modified request is forwarded to the appropriate service or backend.
### Configuration Properties:
- **`prefix`** (`string`): The prefix to be added to the URL path. Ensure the prefix starts with a / to maintain proper URL formatting.

### Example: AddPrefix Middleware Configuration

Here’s an example of an `addPrefix` middleware configuration in YAML:

```yaml
middlewares:
  - name: addPrefix
    type: addPrefix
    rule:
      prefix: /prefix
```
In this example:

- The middleware adds `/prefix` to the beginning of every incoming URL path.
- For instance, a request to `/api/resource` would be transformed into `/prefix/api/resource`

### When to Use AddPrefix
- To ensure requests have a consistent prefix before reaching the backend services.
- To manage routing for services with path-based prefixes.

For scenarios requiring more complex URL modifications, consider using middleware like `RedirectRegex`.