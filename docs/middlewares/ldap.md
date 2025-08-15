---
title: LDAP auth
layout: default
parent: Middlewares
nav_order: 14
---

# LDAP Authentication Middleware

The LDAP middleware for Goma Gateway provides secure authentication using LDAP (Lightweight Directory Access Protocol) servers with HTTP Basic Authentication. This middleware validates user credentials against your organization's directory service and can forward authenticated user information to backend services.

## Features

- **LDAP Authentication**: Seamless integration with existing LDAP/Active Directory infrastructure
- **Built-in Rate Limiting**: Protects LDAP servers from excessive authentication requests
- **Connection Pooling**: Optimizes performance with configurable connection management
- **Username Forwarding**: Passes authenticated usernames to backend services via headers
- **TLS Support**: Secure connections with StartTLS and certificate validation options
- **Flexible User Filtering**: Customizable LDAP queries for user authentication and authorization

## How It Works

1. Client sends request with HTTP Basic Authentication credentials
2. Middleware extracts username/password from Authorization header
3. Establishes connection to LDAP server using configured bind credentials
4. Searches for user using the provided user filter
5. Attempts to bind with user's credentials for authentication
6. On success, optionally forwards username to backend service
7. Rate limiting prevents abuse and protects LDAP infrastructure

## Configuration

### Basic Configuration

```yaml
middlewares:
  - name: ldap-auth
    type: ldap
    paths:
      - /*
    rule:
      url: ldap://ldap.example.com:389 # or use env ${ENV_NAME}
      baseDN: dc=example,dc=com
      bindDN: uid=service-account,ou=people,dc=example,dc=com
      bindPass: service_account_password
      userFilter: "(uid=%s)"
```

### Complete Configuration Example

```yaml
middlewares:
  - name: ldap-auth
    type: ldap
    paths:
      - /api/*
      - /admin/*
    rule:
      # Authentication Settings
      realm: "Company LDAP"              # Authentication realm displayed in browser
      forwardUsername: true              # Forward username to backend (default: false)
      
      # LDAP Server Configuration
      url: ldaps://ldap.company.com:636  # LDAP server URL (ldap:// or ldaps://)
      baseDN: dc=company,dc=com          # Base DN for user searches
      
      # Service Account Credentials
      bindDN: cn=gateway-service,ou=service-accounts,dc=company,dc=com
      bindPass: secure_service_password
      
      # User Search Configuration
      userFilter: "(&(objectClass=inetOrgPerson)(uid=%s)(memberOf=cn=gateway-users,ou=groups,dc=company,dc=com))"
      
      # TLS Configuration
      startTLS: false                    # Use StartTLS for plain LDAP connections
      insecureSkipVerify: false          # Skip certificate verification (not recommended for production)
      
      # Performance Optimization
      connPool:
        size: 10                         # Connection pool size
        burst: 20                        # Rate limiting burst capacity
        ttl: 300s                        # Connection time-to-live
```

## Configuration Parameters

### Required Parameters

| Parameter    | Description                                   | Example                        |
|--------------|-----------------------------------------------|--------------------------------|
| `url`        | LDAP server URL with protocol and port        | `ldap://ldap.example.com:389`  |
| `baseDN`     | Base Distinguished Name for searches          | `dc=example,dc=com`            |
| `bindDN`     | Service account DN for LDAP operations        | `cn=service,dc=example,dc=com` |
| `bindPass`   | Service account password                      | `password123`                  |
| `userFilter` | LDAP filter to locate users (`%s` = username) | `(uid=%s)`                     |

### Optional Parameters

| Parameter            | Type    | Default                 | Description                                              |
|----------------------|---------|-------------------------|----------------------------------------------------------|
| `realm`              | string  | `"LDAP Authentication"` | Authentication realm name                                |
| `forwardUsername`    | boolean | `false`                 | Forward username to backend in `X-Forwarded-User` header |
| `startTLS`           | boolean | `false`                 | Upgrade plain connection to TLS                          |
| `insecureSkipVerify` | boolean | `false`                 | Skip TLS certificate verification                        |

### Connection Pool Configuration

| Parameter        | Type     | Default | Description                        |
|------------------|----------|---------|------------------------------------|
| `connPool.size`  | integer  | `5`     | Number of connections to maintain  |
| `connPool.burst` | integer  | `10`    | Maximum burst requests allowed     |
| `connPool.ttl`   | duration | `60s`   | Connection lifetime before refresh |

## Common LDAP Filter Examples

### Basic User Authentication
```yaml
userFilter: "(uid=%s)"                    # Match by username
userFilter: "(sAMAccountName=%s)"         # Active Directory username
userFilter: "(mail=%s)"                   # Match by email address
```

### Group-Based Authorization
```yaml
# Users must be members of specific group
userFilter: "(&(uid=%s)(memberOf=cn=app-users,ou=groups,dc=example,dc=com))"

# Multiple group membership (OR condition)
userFilter: "(&(uid=%s)(|(memberOf=cn=admins,ou=groups,dc=example,dc=com)(memberOf=cn=developers,ou=groups,dc=example,dc=com)))"

# Active Directory group membership
userFilter: "(&(sAMAccountName=%s)(memberOf=CN=Gateway Users,OU=Security Groups,DC=company,DC=com))"
```

### Advanced Filters
```yaml
# Exclude disabled accounts and require group membership
userFilter: "(&(uid=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(memberOf=cn=active-users,ou=groups,dc=example,dc=com))"

# Multiple object classes
userFilter: "(&(|(objectClass=person)(objectClass=inetOrgPerson))(uid=%s))"
```

## Route Integration

### Simple Route Protection
```yaml
routes:
  - path: /api
    name: protected-api
    backends:
      - endpoint: https://internal-api.company.com
    middlewares:
      - ldap-auth
```

### Multiple Middleware Chain
```yaml
routes:
  - path: /admin
    name: admin-panel
    backends:
      - endpoint: https://admin.company.com
    middlewares:
      - rate-limit        # Apply rate limiting first
      - ldap-auth         # Then authenticate
      - audit-log         # Finally log access
```

### Environment Variables

Use environment variables for sensitive configuration:

```yaml
middlewares:
  - name: ldap-auth
    type: ldap
    rule:
      url: ${LDAP_URL}
      bindDN: ${LDAP_BIND_DN}
      bindPass: ${LDAP_BIND_PASSWORD}
      # ... other configuration
```

