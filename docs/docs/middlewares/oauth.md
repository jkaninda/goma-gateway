---
title: OAuth auth
sidebar_label: OAuth auth
sidebar_position: 7
---

# OAuth middleware

`type: oauth` and `type: oauth2` were aliases for the
[OpenID Connect middleware](oidc.md), and were **removed in v1.0**. Use
`type: oidc`, which is where this middleware is documented.

A configuration that still uses either will not start. The rule keys that moved
at the same time are listed under
[Migrating from `type: oauth`](oidc.md#migrating-from-type-oauth).
