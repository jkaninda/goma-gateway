---
title: LDAP auth
sidebar_label: LDAP auth
sidebar_position: 14
---

# LDAP Authentication Middleware

The LDAP middleware for Goma Gateway provides secure authentication using LDAP (Lightweight Directory Access Protocol) servers with HTTP Basic Authentication. This middleware validates user credentials against your organization's directory service and can forward authenticated user information to backend services.

## Features

- **LDAP Authentication**: Seamless integration with existing LDAP/Active Directory infrastructure
- **Built-in Rate Limiting**: Limits how many authentication attempts reach the LDAP server (`connPool`)
- **Username Forwarding**: Passes authenticated usernames to backend services via a header
- **TLS Support**: Secure connections with StartTLS and certificate validation options
- **Flexible User Filtering**: Customizable LDAP queries for user authentication and authorization

## How It Works

1. Client sends request with HTTP Basic Authentication credentials
2. Middleware extracts username/password from Authorization header
3. Checks the authentication rate limit; when it is exceeded the client receives `429 Too Many Requests` with a `Retry-After` header
4. Connects to the LDAP server and binds with the service account (`bindDN` / `bindPass`), or searches anonymously when they are empty
5. Searches `baseDN` (whole subtree) with `userFilter`, the username escaped for LDAP; exactly one entry must match
6. Binds as the found entry with the user's password
7. On success, optionally forwards the username to the backend; on failure, responds `401 Unauthorized`

## Configuration

### Basic Configuration

```yaml
middlewares:
  - name: ldap-auth
    type: ldapAuth
    paths:
      - /.*
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
      - /api/.*
      - /admin/.*
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
      
      # Authentication rate limit
      connPool:
        size: 10                         # Attempts allowed per ttl window
        burst: 20                        # Burst capacity
        ttl: 1m                          # Window length
```

## Configuration Parameters

### Required Parameters

| Parameter    | Description                                   | Example                        |
|--------------|-----------------------------------------------|--------------------------------|
| `url`        | LDAP server URL with protocol and port        | `ldap://ldap.example.com:389`  |
| `baseDN`     | Base Distinguished Name for searches          | `dc=example,dc=com`            |
| `userFilter` | LDAP filter to locate users (`%s` = username) | `(uid=%s)`                     |

### Optional Parameters

| Parameter            | Type    | Default                 | Description                                              |
|----------------------|---------|-------------------------|----------------------------------------------------------|
| `bindDN`             | string  | empty                   | Service account DN used for the user search. Anonymous search when `bindDN` or `bindPass` is empty |
| `bindPass`           | string  | empty                   | Service account password                                 |
| `realm`              | string  | `"Restricted"`          | Authentication realm name                                |
| `forwardUsername`    | boolean | `false`                 | Forward the username to the backend in a `username` request header |
| `startTLS`           | boolean | `false`                 | Upgrade a plain `ldap://` connection to TLS              |
| `insecureSkipVerify` | boolean | `false`                 | Skip TLS certificate verification                        |

### Authentication Rate Limit (`connPool`)

Despite its name, `connPool` does not pool connections: each authentication
opens its own LDAP connection. It configures a rate limit on authentication
attempts, shared by all clients of the middleware, that protects the directory.

| Parameter        | Type     | Default | Description                                       |
|------------------|----------|---------|---------------------------------------------------|
| `connPool.size`  | integer  | `10`    | Attempts allowed per `ttl` window                 |
| `connPool.burst` | integer  | `20`    | Attempts allowed in a burst above that rate       |
| `connPool.ttl`   | duration | `1m`    | Window length; also sent as `Retry-After` on 429  |

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
      - rate-limit
      - ldap-auth
```

### Environment Variables

Use environment variables for sensitive configuration:

```yaml
middlewares:
  - name: ldap-auth
    type: ldapAuth
    rule:
      url: ${LDAP_URL}
      bindDN: ${LDAP_BIND_DN}
      bindPass: ${LDAP_BIND_PASSWORD}
      # ... other configuration
```

