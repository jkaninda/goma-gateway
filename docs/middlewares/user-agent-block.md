---
title: User Agent Block
layout: default
parent: Middlewares
nav_order: 15
---

# User Agent Block Middleware

This middleware blocks HTTP requests based on the User-Agent header, commonly used to restrict access by bots or unwanted crawlers.

## Configuration Example

Below is an example configuration demonstrating how to set up the `userAgentBlock` middleware to block specific bots by their User-Agent strings:

```yaml
middlewares:
  - name: block-bots
    type: userAgentBlock
    paths:
      - /*
    rule:
      userAgents:
        - Googlebot
        - Bingbot
        - Slurp
        - Yahoo
        - YandexBot
        - Yeti
        - AhrefsBot
        - SemrushBot
        - DotBot
        - Exabot
        - facebot
        - ia_archiver
        - MJ12bot
        - Bytespider
        - archive.org_bot
```
