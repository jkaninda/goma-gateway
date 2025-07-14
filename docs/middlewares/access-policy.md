---
title: Access Policy
layout: default
parent: Middlewares
nav_order: 3
---


### Access Policy Middleware
The Access Policy middleware controls route access by either allowing or denying requests based on defined rules.
It supports two actions: `ALLOW` and `DENY`.

This middleware applies to the entire route, eliminating the need to specify individual path fields.


### How It Works
1. **Define an action:** Specify whether the middleware should `ALLOW` or `DENY` access.

2. **Set sourceRanges:** Provide a list of IP addresses, IP ranges, or CIDR blocks to which the policy applies. Requests originating from these sources will be evaluated based on the defined action.

#### Example Configuration
Here’s an example of an Access Policy middleware configuration in YAML:

```yaml
middlewares:
   - name: access-policy
     type: accessPolicy
     rule:
        action: DENY  # Specify either DENY or ALLOW
        sourceRanges:
           - 192.168.1.1        # Single IP address
           - 10.42.1.1-10.42.1.100 # IP range
           - 10.42.1.1/16       # CIDR block
```
## Parameters:

- `action`: Defines whether to `ALLOW` or `DENY` access. Set this to either `ALLOW` or `DENY`.
- `sourceRanges`: A list of IP addresses, IP ranges, or CIDR blocks that the policy applies to. Requests from these sources will be evaluated according to the specified action.
