---
title: Overview
sidebar_label: Overview
sidebar_position: 1
---
# Middlewares

Middleware functions are executed before or after a route callback, enabling you to extend the behavior of your routes.

They are an excellent way to implement features like API authentication, access control, or request validation. 

With Goma, you can create custom middleware tailored to your needs and apply them to your routes seamlessly.

## Supported Middleware Types

- **Authentication Middleware**
  - **ForwardAuth**: delegates authorization to a backend service, determining access based on the service's HTTP response.
  - **Basic-Auth**: Verifies credentials through Basic Authentication.
  - **OAuth**: Supports OAuth-based authentication flows.
  - **LDAP**: servers with HTTP Basic Authentication

- **Rate Limiting Middleware**
  - **In-Memory Client IP Based**: Throttles requests based on the client’s IP address using an in-memory store.
  - **Distributed Rate Limiting**: Leverage Redis for scalable, client IP-based rate limits.

- **Access Middleware**
  - Validates user permissions or access rights for specific route paths.
- **Access Policy Middleware**
  - Controls route access by either `allowing` or `denying` requests based on defined rules.
- **Geo Block Middleware**
  - Controls route access by country (GeoIP), `allowing` or `denying` requests, with optional country-header enrichment for the upstream.

Middleware provides a flexible and powerful way to enhance the functionality, security, and performance of your API.

## Configuration Options

- **`name`** (`string`): Name of the middleware without white space.
- **`type`** (`string`): Type of the middleware.
- **`paths`** (`array of string`): Paths to prevent or protect. See [Path patterns](#path-patterns).
- **`rule`** (`dictionary`): Middleware rule, changes depending on their type.

## Path patterns

A path is matched as a **regular expression** first, and as a wildcard only if it
is not valid regex. Prefer the regular expression form:

```yaml
paths:
  - /.*                # everything on the route
  - /admin/.*          # everything under /admin
  - ^/api/v[0-9]+/.*$  # anchored, matches only at the start
```

Two things are worth knowing before you write a rule:

**Patterns are unanchored.** `/admin` matches any path *containing* `/admin`,
including `/public/admin/notes`. Anchor with `^` and `$` when you mean a
specific path:

```yaml
  - ^/admin$        # exactly /admin
  - ^/admin(/.*)?$  # /admin and everything under it
```

**Matching is case-insensitive.** `/admin/.*` also matches `/Admin/users`, which
is deliberate: many backends treat the two as the same resource, and a rule that
only covered the lowercase form could be walked around by changing the case.

The wildcard form (`/admin/*`) is still accepted for existing configurations. It
only supports a trailing `*` — a pattern like `/tenant/*/api/*` matches nothing —
and the gateway logs the regex form to replace it with the first time it sees
one.
