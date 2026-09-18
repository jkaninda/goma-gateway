---
title: Upgrade Notes
sidebar_label: Upgrade Notes
sidebar_position: 9
---

## Upgrade Notes

Release-by-release notes for configuration changes that need action when you
upgrade.

Start with the release you are moving **to**. If you are skipping several
versions, work through each note in order — the migrations are cumulative.

| Release               | What changed                                                    |
|-----------------------|------------------------------------------------------------------|
| [v1.0](./v1.0.md)     | **Breaking.** Every key deprecated during v0.x is removed.      |
| [v0.7.0](./v0.7.0.md) | TLS certificates move from `tls.keys` to `tls.certificates`.    |
| [v0.6.0](./v0.6.0.md) | CORS and error interception move to middlewares.                |
| [v0.3.0](./v0.3.0.md) | Configuration layout changes.                                   |
| [v0.2.8](./v0.2.8.md) | Configuration layout changes.                                   |
| [v0.2.4](./v0.2.4.md) | Configuration layout changes.                                   |
