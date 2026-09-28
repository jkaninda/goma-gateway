---
title: User Manual
sidebar_label: User Manual
sidebar_position: 5
---

## User Manual

The main top-level sections of a Goma Gateway configuration file are `gateway`
(entry points, TLS, monitoring and the routes), `middlewares`, and
`certManager` for automatic certificates.

- [Gateway](gateway.md) — global settings: entry points, timeouts, TLS,
  monitoring, networking and on-demand reload.
- [Route](route.md) — how requests are matched and forwarded to backends.
- [Extra Config](extra-config.md) — split routes and middlewares into
  additional files.
- [Providers](providers.md) — load routes and middlewares dynamically from
  files, HTTP endpoints or Git repositories.
