---
title: AddPrefix
layout: default
parent: Middleware
nav_order: 8
---


### AddPrefix middleware

The `AddPrefix` middleware adds a prefix to the URL path of incoming requests.

## How It Works:
- The `AddPrefix` middleware intercepts incoming requests.
- It adds the specified prefix to the URL path.
- The request is then forwarded to the appropriate service.

### Example: AddPrefix Middleware Configuration

Here’s an example of an `addPrefix` middleware configuration in YAML:

```yaml
  - name: addPrefix
    type: addPrefix
    rule:
      prefix: /prefix
```