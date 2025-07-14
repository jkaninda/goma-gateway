---
title: RewriteRegex
layout: default
parent: Middlewares
nav_order: 9
---


### RewriteRegex middleware
The `rewriteRegex` middleware allows dynamic rewriting of URL paths using regular expressions. It is ideal for complex rewrite rules that cannot be handled by simple string-based rewrites.
## How It Works:
- **Interception**: The `rewriteRegex` middleware intercepts incoming requests and evaluates the URL path.
- **Pattern Matching**: The middleware checks the path against a specified regular expression (`pattern`).
- **Rewrite Action**: If the pattern matches, the middleware rewrites the path using the provided `replacement`.

### Example: RegexRewrite Middleware Configuration

Here’s an example of a `RegexRewrite` middleware configuration in YAML:

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

### When to Use RewriteRegex
- 
- When simple rewrites (like those handled by the `rewrite` property) are not enough.
- When you need to handle dynamic path segments or complex patterns.

For straightforward rewrites, consider using the route `rewrite` property instead to reduce complexity.