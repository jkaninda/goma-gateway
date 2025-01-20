---
title: Access
layout: default
parent: Middleware
nav_order: 2
---


# Access Middleware

Access middleware is used to restrict access to specific routes or route paths. This helps secure your application by preventing unauthorized access to sensitive endpoints.

## Key Features
- Rule: To block all subpaths of a route, append /* to the path explicitly.

- Tip: Always test configurations thoroughly in a staging environment before applying them to production.

---
### Example: Access Middleware Configuration

The following example demonstrates how to define blocked paths using the access middleware:

```yaml
middlewares:
# Middleware configuration to block specific paths
    - name: api-blocked-paths
      type: access
      paths:
        - /swagger-ui       # Blocks only /swagger-ui
        - /v2/swagger-ui    # Blocks only /v2/swagger-ui
        - /api-docs/*       # Explicitly blocks /api-docs and all subpaths
```
### Explanation:

- `/swagger-ui`: Only the exact path `/swagger-ui` is blocked.
- `/v2/swagger-ui`: Only the exact path `/v2/swagger-ui` is blocked.
- `/api-docs/*`: The path `/api-docs` and all subpaths (e.g.,` /api-docs/v1`) are blocked due to the `/*` wildcard.

### Applying Access Middleware to Routes
Here’s how to attach the access middleware to a specific route:

```yaml
routes:
  - path: /protected
    name: protected
    rewrite: /
    destination: 'https://example.com'
    methods: [POST, PUT, GET]
    healthCheck: {}
    cors: {}
    middlewares:
      - api-blocked-paths
```

## Best Practices

- Consistency: Ensure all sensitive paths are accounted for in the middleware configuration.
- Granularity: Use `/*` judiciously to block subpaths where necessary.
- Testing: Validate all configurations in a non-production environment before deployment.

By adhering to these guidelines, you can effectively use `access` middleware to secure your application routes.