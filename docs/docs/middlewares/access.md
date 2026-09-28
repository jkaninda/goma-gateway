---
title: Access
sidebar_label: Access
sidebar_position: 2
---


# Access Middleware

The access middleware blocks requests to specific paths of a route. Use it to keep
sensitive endpoints, such as admin panels, debug endpoints or API docs,
unreachable through the gateway.

## Configuration

```yaml
middlewares:
  - name: api-blocked-paths
    type: access
    paths:
      - /docs                   # /docs and everything below it
      - /admin                  # /admin and everything below it
      - "^/api/v[0-9]+/temp.*"  # versioned temp endpoints
    rule:                       # Optional
      statusCode: 404           # Default: 403
```

### Configuration Options

| Parameter         | Type    | Required | Default | Description                                    |
|-------------------|---------|----------|---------|------------------------------------------------|
| `paths`           | array   | Yes      | -       | Path patterns to block                         |
| `rule.statusCode` | integer | No       | `403`   | HTTP status code returned for blocked requests |

:::warning
An access middleware without `paths` blocks **every** path of the route it is
attached to.
:::

### Path Matching Behavior

`paths` entries are regular expressions, matched case-insensitively from the
start of the request path. See [Path patterns](overview.md#path-patterns) for
the full rules.

- **Prefix matching**: `/docs` blocks `/docs`, `/docs/swagger` and also `/docs-v2`; use `^/docs(/.*)?$` to block only `/docs` and its subpaths
- **Route-relative**: on a route at `/api`, `/docs` also blocks `/api/docs`
- **Root path**: `/` blocks all requests to the route
- **Anchored patterns**: a pattern starting with `^` is matched against the full request path only

## Applying Middleware to Routes

```yaml
routes:
  - path: /api
    name: api-route
    backends:
      - endpoint: https://api.example.com
    methods: [GET, POST, PUT, DELETE]
    middlewares:
      - api-blocked-paths
```

## Advanced Path Patterns

```yaml
middlewares:
  - name: advanced-blocking
    type: access
    paths:
      # Temporary endpoints across API versions
      - "^/api/v[0-9]+/temp.*"

      # Destructive user actions
      - "^/users/[0-9]+/(delete|remove)$"

      # /debug and everything below it
      - "^/debug(/.*)?$"

      # Files that might expose sensitive data
      - ".*\\.(log|bak|tmp)$"

      # Dynamic admin paths
      - "^/admin-[a-zA-Z0-9]+/.*"
    rule:
      statusCode: 404
```

| Pattern                             | Matches                             | Does not match      |
|-------------------------------------|-------------------------------------|---------------------|
| `^/api/v[0-9]+/temp.*`              | `/api/v1/temp`, `/api/v2/temp/data` | `/api/temp`         |
| `^/users/[0-9]+/(delete\|remove)$`  | `/users/42/delete`                  | `/users/42/deleted` |
| `^/debug(/.*)?$`                    | `/debug`, `/debug/vars`             | `/debugger`         |
| `.*\.(log\|bak\|tmp)$`              | `/logs/app.log`, `/db.bak`          | `/app.logs`         |
