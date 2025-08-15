---
title: Access Policy
layout: default
parent: Middlewares
nav_order: 3
---


# Access Policy Middleware

The Access Policy middleware provides IP-based access control for routes by allowing or denying requests based on predefined rules. This middleware applies globally to the entire route, eliminating the need to configure individual path-level restrictions.

## Overview

Access Policy middleware supports two primary actions:
- **ALLOW**: Permits requests from specified source ranges
- **DENY**: Blocks requests from specified source ranges

## Configuration

### Basic Structure

```yaml
middlewares:
  - name: access-policy
    type: accessPolicy
    rule:
      action: <ALLOW|DENY>
      sourceRanges:
        - <ip_address_or_range>
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `action` | String | Yes | Defines the policy action. Must be either `ALLOW` or `DENY` |
| `sourceRanges` | Array | Yes | List of IP addresses, IP ranges, or CIDR blocks to which the policy applies |

### Source Range Formats

The `sourceRanges` parameter accepts three formats:

- **Single IP Address**: `192.168.1.1`
- **IP Range**: `10.42.1.1-10.42.1.100`
- **CIDR Block**: `10.42.1.0/24`

## Examples

### Example 1: Block Specific IP Ranges

```yaml
middlewares:
  - name: block-internal-networks
    type: accessPolicy
    rule:
      action: DENY
      sourceRanges:
        - 192.168.1.0/24      # Block entire subnet
        - 10.0.0.1-10.0.0.50   # Block IP range
        - 172.16.1.1           # Block single IP
```

### Example 2: Allow Only Specific Networks

```yaml
middlewares:
  - name: allow-office-only
    type: accessPolicy
    rule:
      action: ALLOW
      sourceRanges:
        - 203.0.113.0/24       # Office network
        - 198.51.100.1         # VPN gateway
```

## How It Works

1. **Request Evaluation**: When a request arrives, the middleware checks the client's IP address against the configured `sourceRanges`
2. **Action Application**: If the IP matches any range in the list, the specified `action` is applied
3. **Default Behavior**:
    - For `DENY` policies: Requests from unlisted IPs are allowed
    - For `ALLOW` policies: Requests from unlisted IPs are blocked

## Common Use Cases

- **Geoblocking**: Restrict access based on geographic regions
- **Internal API Protection**: Allow only internal network access
- **Security Hardening**: Block known malicious IP ranges
- **Compliance Requirements**: Implement network-based access controls