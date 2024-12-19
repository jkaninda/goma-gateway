---
title: RegexRewrite
layout: default
parent: Middleware
nav_order: 9
---


### RegexRewrite middleware
The `RedirectRegex` middleware rewrites the URL path based on a regular expression match.

## How It Works:
- The `RegexRewrite` middleware intercepts incoming requests.
- It matches the incoming URL path against the regex (`^/oldpath/(.*)`).
- If it matches, it rewrites the URL path using the replacement (`/newpath/$1`).

### Example: RegexRewrite Middleware Configuration

Here’s an example of a `RegexRewrite` middleware configuration in YAML:

```yaml
middlewares:
  - name: rewrite-oldpath-to-newpath
    type: redirectRegex
    rule:
      pattern: ^/oldpath/(.*)
      replacement: /newpath/$1
```