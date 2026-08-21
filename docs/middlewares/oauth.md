---
title: OAuth auth
layout: default
parent: Middlewares
nav_order: 7
---

# OAuth middleware

`type: oauth` and `type: oauth2` are deprecated aliases for the
[OpenID Connect middleware](oidc.md), which is where this middleware is
documented.

Existing configurations keep working. The gateway logs which field to move to
when it loads one, and the replacements are listed under
[Migrating from `type: oauth`](oidc.md#migrating-from-type-oauth).
