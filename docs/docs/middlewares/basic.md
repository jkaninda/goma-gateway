---
title: Basic auth
sidebar_label: Basic auth
sidebar_position: 4
---


# Basic Auth Middleware

The basic-auth middleware protects route paths with HTTP Basic Authentication: a
request must carry a valid username and password in its `Authorization` header.

Types: `basicAuth` or `basic`.

### Example: Basic-Auth Middleware Configuration

```yaml
middlewares:
  - name: basic-auth
    type: basicAuth
    paths:
      - /admin  # /admin and every path below it
    rule:
      realm: your-realm        # Optional, default "Restricted"
      forwardUsername: true    # Forward the authenticated username to the backend
      users:
        # Generate your own hash; the ones on this page are examples of the
        # supported formats, not credentials to copy into a deployment.
        - username: admin
          password: "$2y$12$REPLACE.WITH.YOUR.OWN.BCRYPT.HASH" # bcrypt hash
        - username: user1
          password: "{SHA}0DPiKuNIrrVmD8IUCuw1hQxNqZc=" # SHA-1 hash
        - username: user2
          password: password # Plaintext password
        - username: ${USER_NAME}
          password: ${PASSWORD} # Environment variables
```

When `paths` is omitted, every path of the route is protected. See
[Path patterns](overview.md#path-patterns).

### Configuration Options

| Option            | Type    | Default      | Description                                                                                      |
|-------------------|---------|--------------|--------------------------------------------------------------------------------------------------|
| `users`           | list    | **required** | `username` / `password` pairs. The legacy `"username:password"` string form is still accepted.   |
| `realm`           | string  | `Restricted` | Realm sent in the `WWW-Authenticate` header.                                                     |
| `forwardUsername` | boolean | `false`      | Set a `username` request header with the authenticated user for the backend.                     |

Supported password formats:

- bcrypt (`$2a$`, `$2b$`, `$2x$`, `$2y$`)
- Apache APR1-MD5 (`$apr1$`) and MD5-crypt (`$1$`)
- SHA-1 (`{SHA}...`)
- plaintext

A value that starts with `$` or `{` but uses none of these schemes is rejected,
never compared as a plaintext password.

A request without valid credentials receives `401 Unauthorized` with a
`WWW-Authenticate: Basic realm="..."` header. The gateway always removes a
client-supplied `username` header, so a backend can trust it when
`forwardUsername` is enabled.

### Applying Basic-Auth Middleware to a Route

```yaml
  routes:
    - path: /
      name: basic-auth-route
      backends:
        - endpoint: https://example.com
      methods: [POST, PUT, GET]
      middlewares:
        - basic-auth
```

### Create user and password

```shell
docker run --rm \
  --entrypoint htpasswd \
  httpd:2 -Bbn admin password
```
