---
title: Access
layout: default
parent: Middlewares
nav_order: 2
---


# Access Middleware

Access middleware provides route-level access control by blocking requests to specified paths. This security feature helps protect sensitive endpoints from unauthorized access.

## Configuration

Access middleware uses a path-based blocking system where you define which routes should be restricted.

### Basic Configuration

```yaml
middlewares:
  - name: api-blocked-paths
    type: access
    paths:
      - /docs          # Blocks /docs and all subpaths
      - /admin         # Blocks /admin and all subpaths
      - /internal/api  # Blocks specific internal endpoints
      - "^/api/v[0-9]+/temp.*"  # Regex: blocks versioned temp endpoints
    rule:              # Optional configuration
      statusCode: 404  # Custom HTTP status code (default: 403)
```

### Configuration Options

| Parameter         | Type    | Required | Default | Description                                    |
|-------------------|---------|----------|---------|------------------------------------------------|
| `name`            | string  | Yes      | -       | Unique identifier for the middleware           |
| `type`            | string  | Yes      | -       | Must be set to `access`                        |
| `paths`           | array   | Yes      | -       | List of paths to block                         |
| `rule.statusCode` | integer | No       | 403     | HTTP status code returned for blocked requests |

### Path Matching Behavior

- **Exact and prefix matching**: `/docs` blocks both `/docs` and `/docs/swagger`
- **Root path**: `/` blocks all requests to the application
- **Nested paths**: `/api/v1/internal` blocks only that specific path and its subpaths
- **Regex patterns**: Use regular expressions for advanced path matching with complex patterns

## Applying Middleware to Routes

Attach the access middleware to routes by referencing its name in the route configuration:

```yaml
routes:
  - path: /api
    name: api-route
    rewrite: /
    backends:
      - endpoint: https://api.example.com
    methods: [GET, POST, PUT, DELETE]
    middlewares:
      - api-blocked-paths  # Reference to middleware defined above
```

### Advanced Path Patterns with Regex

For complex path matching requirements, use regular expressions:

```yaml
middlewares:
  - name: advanced-blocking
    type: access
    paths:
      # Block all temporary endpoints across API versions
      - "^/api/v[0-9]+/temp.*"
      
      # Block endpoints with sensitive parameters
      - "^/users/[0-9]+/(delete|remove)$"
      
      # Block debug endpoints with optional trailing slashes
      - "^/debug(/.*)?/?$"
      
      # Block file extensions that might expose sensitive data
      - ".*\\.(log|bak|tmp)$"
      
      # Block dynamic admin paths
      - "^/admin-[a-zA-Z0-9]+/.*"
    rule:
      statusCode: 404
```

### Regex Pattern Examples

| Pattern                                   | Matches                             | Description                   |
|-------------------------------------------|-------------------------------------|-------------------------------|
| `^/api/v[0-9]+/temp.*`                    | `/api/v1/temp`, `/api/v2/temp/data` | Versioned temporary endpoints |
| `^/users/[0-9]+/delete# Access Middleware |                                     |                               |

Access middleware provides route-level access control by blocking requests to specified paths. This security feature helps protect sensitive endpoints from unauthorized access.

## Configuration

Access middleware uses a path-based blocking system where you define which routes should be restricted.

### Basic Configuration

```yaml
middlewares:
  - name: api-blocked-paths
    type: access
    paths:
      - /docs          # Blocks /docs and all subpaths
      - /admin         # Blocks /admin and all subpaths
      - /internal/api  # Blocks specific internal endpoints
      - "^/api/v[0-9]+/temp.*"  # Regex: blocks versioned temp endpoints
    rule:              # Optional configuration
      statusCode: 404  # Custom HTTP status code (default: 403)
```
