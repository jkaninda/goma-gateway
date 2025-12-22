---
title: User Agent Block
layout: default
parent: Middlewares
nav_order: 16
---

# User Agent Block Middleware

This middleware provides HTTP request filtering based on User-Agent headers, enabling you to control access by blocking specific bots, crawlers, or unwanted clients.

## Overview

The `userAgentBlock` middleware examines incoming HTTP requests and blocks those whose User-Agent header matches specified patterns. This is particularly useful for:

- Preventing unwanted bot traffic
- Reducing server load from aggressive crawlers
- Blocking scrapers or automated tools
- Implementing selective access control

## Configuration

### Basic Structure

```yaml
middlewares:
  - name: <middleware-name>
    type: userAgentBlock
    rule:
      userAgents:
        - <user-agent-pattern>
```

### Parameters

| Parameter         | Type   | Required | Description                                   |
|-------------------|--------|----------|-----------------------------------------------|
| `name`            | string | Yes      | Unique identifier for the middleware instance |
| `type`            | string | Yes      | Must be set to `userAgentBlock`               |
| `rule.userAgents` | array  | Yes      | List of User-Agent patterns to block          |


### User-Agent Matching

The middleware supports:
- **Exact matching**: Full User-Agent string comparison
- **Substring matching**: Partial string matching within the User-Agent
- **Case-insensitive matching**: Automatically handles case variations

## Configuration Examples

### Example 1: Block Common Bots

```yaml
middlewares:
  - name: block-search-bots
    type: userAgentBlock
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
