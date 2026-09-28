---
title: Middlewares
sidebar_label: Middlewares
sidebar_position: 6
---

## Middlewares

Middlewares add authentication, access control, traffic shaping and request or
response rewriting to a route, at the gateway and before any request reaches a
backend.

- [Overview](overview.md): how middlewares are defined and attached, the list of
  every middleware type, and how `paths` patterns are matched.
- [Authentication](overview.md#authentication): Basic auth, JWT, OpenID Connect,
  LDAP and ForwardAuth.
- [Access Control](overview.md#access-control): path blocking, IP and country
  policies, User-Agent blocking, rate limiting and body size limits.
- [Request and Response](overview.md#request-and-response): path prefixes and
  rewrites, query stripping, request and response headers, CORS and caching.
- [Redirects](overview.md#redirects): fixed, regex-based and scheme redirects.
- [Observability and Errors](overview.md#observability-and-errors): access log
  enrichment and custom error responses.
