---
title: Providers
sidebar_label: Providers
sidebar_position: 12
---

# Providers

Providers in **Goma Gateway** enable **dynamic configuration management** by automatically discovering and loading routes and middleware from external sources.

Instead of manual editing configuration files, providers allow you to adopt modern patterns such as **GitOps**, **service discovery**, and **centralized configuration management**.

---

## Why Use Providers?

Providers unlock a more scalable and automated way to manage your gateway:

- **Dynamic Discovery**  
  Automatically detect and configure services without manual updates

- **GitOps Integration**  
  Store and version gateway configuration in Git repositories

- **Centralized Management**  
  Control multiple gateway instances from a single source

- **Zero-Downtime Updates**  
  Apply configuration changes without restarting the gateway

---

## Available Providers

Goma Gateway supports both **built-in** and **external** providers.

### Built-in Providers

- **File** — Load configuration from the local filesystem (with hot reload)
- **HTTP** — Fetch configuration from remote APIs
- **Git** — Pull configuration from Git repositories (GitOps)

### External Providers

- **Docker / Swarm** — Generate configuration from container labels
- **Kubernetes** — Integrate with CRDs and annotations
- **HTTP API** — Manage configuration via REST APIs

---

## How Providers Work

All providers follow a continuous synchronization cycle:

```mermaid
flowchart LR
    A[Provider Source] -->|Poll / Watch| B[Fetch Config]
    B -->|Parse| C[Validate]
    C -->|Valid| D[Apply Routes & Middleware]
    C -->|Invalid| E[Log Error & Keep Previous Config]
    D -->|Live| F[Active Gateway]
    E -->|Fallback| F
````

### Key Behaviors

* **Safe updates** — Invalid configurations never break the gateway
* **Fallback mechanism** — Last valid configuration remains active
* **Caching** — HTTP and Git providers cache successful configurations
* **Live reload** — File provider watches for filesystem changes

---

# File Provider

The **File Provider** loads configuration from a local directory and optionally watches for changes.

### Configuration

| Field       | Type   | Required | Description                              |
|-------------|--------|----------|------------------------------------------|
| `enabled`   | bool   | Yes      | Enable the provider                      |
| `directory` | string | Yes      | Directory containing configuration files |
| `watch`     | bool   | No       | Enable automatic reload on file changes  |

### Example

```yaml
gateway:
  providers:
    file:
      enabled: true
      directory: /etc/goma/providers
      watch: true
```

---

# HTTP Provider

The **HTTP Provider** fetches configuration from a remote endpoint.
It is ideal for **centralized configuration services** or control planes.

### Features

* Retry mechanism
* TLS configuration
* Response caching
* Custom headers support

### Supported Content Types

* `application/json`
* `application/yaml`
* `application/x-yaml`
* `text/yaml`

### Configuration

| Field                | Type     | Required | Default                     | Description              |
|----------------------|----------|----------|-----------------------------|--------------------------|
| `enabled`            | bool     | Yes      | —                           | Enable the provider      |
| `endpoint`           | string   | Yes      | —                           | Remote configuration URL |
| `interval`           | duration | No       | 60s                         | Polling interval         |
| `timeout`            | duration | No       | 10s                         | Request timeout          |
| `retryAttempts`      | int      | No       | 3                           | Max retry attempts       |
| `retryDelay`         | duration | No       | 2s                          | Delay between retries    |
| `cacheDir`           | string   | No       | /tmp/goma/cache/config.json | Cache file path          |
| `insecureSkipVerify` | bool     | No       | false                       | Skip TLS verification    |
| `headers`            | map      | No       | —                           | Custom HTTP headers      |

### Example

```yaml
gateway:
  providers:
    http:
      enabled: true
      endpoint: "https://config.example.com/api/gateway/config"
      interval: 60s
      timeout: 10s
      retryAttempts: 3
      retryDelay: 2s
      cacheDir: ""
      insecureSkipVerify: false
      headers:
        X-Goma-Gateway-Id: "goma-prod-01"
        X-Goma-Environment: "production"
        Authorization: "${GOMA_AUTHORIZATION}"
```

### Response Format

The endpoint must return a valid Goma configuration in **YAML or JSON**.

```yaml
version: "1"
timestamp: 2024-10-01T12:00:00Z
checksum: "..."
metadata:
  gateway-id: goma-prod-01
  environment: production

routes:
  - name: api-example
    enabled: true
    path: /
    target: http://api-example:8080

middlewares:
  - name: rate-limit
    type: rateLimit
```

---

# Git Provider

The **Git Provider** retrieves configuration from a Git repository, enabling **GitOps workflows**.

### Supported Authentication

| Type  | Credentials         |
|-------|---------------------|
| token | token               |
| basic | username + password |
| ssh   | private SSH key     |

### Configuration

| Field      | Type     | Required | Default | Description                  |
|------------|----------|----------|---------|------------------------------|
| `enabled`  | bool     | Yes      | —       | Enable the provider          |
| `url`      | string   | Yes      | —       | Git repository URL           |
| `branch`   | string   | No       | main    | Branch to pull               |
| `path`     | string   | No       | /       | Path to configuration        |
| `interval` | duration | No       | 60s     | Sync interval                |
| `cloneDir` | string   | No       | temp    | Local clone directory        |
| `auth`     | object   | No       | —       | Authentication configuration |

#### Authentication fields

| Field                | Type   | Description                                                                  |
|----------------------|--------|------------------------------------------------------------------------------|
| `auth.type`          | string | One of `token`, `basic`, or `ssh`.                                           |
| `auth.token`         | string | Access token. Used when `type: token`.                                       |
| `auth.username`      | string | Username. Used when `type: basic`.                                           |
| `auth.password`      | string | Password. Used when `type: basic`.                                           |
| `auth.sshKeyPath`    | string | Path to a private SSH key file. Used when `type: ssh`.                       |
| `auth.sshKeyData`    | string | The private SSH key inline, **base64-encoded**. Used when `type: ssh`.       |

Provide either `sshKeyPath` or `sshKeyData` — `sshKeyData` suits environments
where the key arrives through an environment variable or a mounted secret
rather than a file on disk.

#### SSH host verification

For `type: ssh`, the Git host is verified before anything is cloned. Configure
one of:

| Field                 | Description                                                                        |
|-----------------------|------------------------------------------------------------------------------------|
| `auth.hostKey`        | A pinned host key in `authorized_keys` format (`ssh-ed25519 AAAA…`). Takes precedence. |
| `auth.knownHostsPath` | An OpenSSH `known_hosts` file. Defaults to `~/.ssh/known_hosts`.                     |

A host that verifies against neither is refused. Without this, anyone able to
MITM or DNS-hijack the route to the Git host could serve an arbitrary
configuration repository — and its routes are merged into the running gateway.

### Example

```yaml
gateway:
  providers:
    git:
      enabled: true
      url: "https://github.com/jkaninda/goma-gateway-production-deployment.git"
      branch: main
      path: /gateway
      interval: 60s
      auth:
        type: token
        token: ${GIT_TOKEN}
      cloneDir: ""
```

---

# Signing configuration bundles

Bundles from the **HTTP** and **Git** providers arrive over the network and are
merged straight into the live gateway. Their routes are sorted longest-path-first,
so a bundle carrying a longer path shadows a real route and receives its traffic
under the gateway's own TLS.

The bundle `checksum` does not protect against this: it is recomputed locally
from the bytes just received, so it detects corruption, not forgery. Sign the
bundles instead.

**1. Generate a keypair** — once, wherever bundles are published from:

```sh
goma config keygen -o signing.key
# Public key  (providers.signing.publicKey): D0lLjT2/f12T4hoi3Zyn9Q1SAW0tTtOzPjTDPwPGHaw=
```

**2. Sign each bundle** before publishing it:

```sh
goma config sign --key-file signing.key gateway/routes.yml
```

`sign` writes a detached Ed25519 signature into the bundle's `signature` field,
over a canonical checksum that excludes the `signature`, `checksum` and
`timestamp` fields — so the value survives re-serialization.

**3. Configure the trust anchor** on the gateway:

```yaml
gateway:
  providers:
    signing:
      publicKey: "D0lLjT2/f12T4hoi3Zyn9Q1SAW0tTtOzPjTDPwPGHaw="
      # Or, to allow more than one signer while rotating a key:
      # publicKeyFile: /etc/goma/signers.pub
    git:
      enabled: true
      # ...
```

Once `publicKey` or `publicKeyFile` is set, an HTTP or Git bundle that is
unsigned, altered after signing, or signed by an unlisted key is **refused**, and
the gateway keeps serving its previous configuration. With neither set the
gateway warns at load and applies bundles unverified, so enabling signing is a
deliberate step rather than a breaking upgrade.

The **file** provider is not covered: it reads a local directory at the same
trust level as the main configuration file.

| Field           | Type   | Required | Description                                                        |
|-----------------|--------|----------|--------------------------------------------------------------------|
| `publicKey`     | string | No       | Base64 Ed25519 public key. Takes precedence over `publicKeyFile`.  |
| `publicKeyFile` | string | No       | File of base64 public keys, one per line; `#` comments allowed.    |

---

# Control Plane vs Data Plane

Goma follows a **modern architecture**:

* **Goma Gateway** → Data plane (fast, lightweight, execution)
* **Goma Admin** → Control plane (management, UI, orchestration)

The gateway intentionally avoids embedding heavy integrations (like Docker or UI) to remain **lightweight, modular, and high-performance**.

---

## Goma Admin (Control Plane)

**Goma Admin** provides a centralized interface to manage gateway configurations.

### Key Features

* Multi-instance management
* File & HTTP provider integration
* Docker-based service discovery
* Import / Export of configurations
* API key management
* Metrics & monitoring (Prometheus)
* OAuth2 integration (Keycloak, Authentik, Gitea)
* Audit logs (configuration history)
* Git synchronization (bi-directional)

---

## Docker Provider (via Goma Admin)

The **Goma Docker Provider** automatically generates configuration from container labels.

This approach is similar to Traefik:

* Routing rules defined via labels
* Automatic service discovery
* No manual configuration required

### Example (Docker Compose)

```yaml
services:
  web-service:
    image: jkaninda/okapi-example
    labels:
      - "goma.enable=true"
      - "goma.port=8080"
      - "goma.hosts=example.com,www.example.com"
```


👉 [Goma Admin](https://github.com/jkaninda/goma-admin)

---

## Miabi (PaaS Control Plane)

[**Miabi**](https://github.com/miabi-io/miabi) is a self-hosted, developer-first
Platform-as-a-Service for containerized apps. It runs **Goma Gateway as its edge
gateway**, and is a good worked example of the control-plane / data-plane split
above in production.

On a Miabi node, application and database ports are not published on the host
unless a host port binding is explicitly approved, so the gateway is the only
listening surface by default. Every app deployed on the platform is reached
through it, and Goma handles:

* **Routing** — per-app routes and service discovery, including load balancing
  and canary traffic splitting
* **TLS** — certificate issuance over ACME `HTTP-01`, wildcard certificates, and
  DNS provider integrations
* **Middleware** — authentication, rate limiting, access control and the rest of
  the middleware chain
* **Security** — a single hardened entry point in front of every workload

### How Miabi drives the gateway

Miabi does not call a gateway API. Its control plane **writes route files into a
directory the gateway watches**, and Goma picks them up and hot-reloads — the
**File Provider** pattern described above. That keeps the integration free of
API tokens and avoids polling entirely.

For clusters other than the one the control plane runs on, the model flips:
each remote cluster runs its **own** Goma instance that **pulls the routes it
serves over HTTP** from the control plane — the **HTTP Provider** pattern. The
gateways stay decoupled, and a remote cluster keeps serving the routes it
already has if the control plane is unreachable.

The same two providers are available to any platform built on Goma; nothing in
this arrangement is specific to Miabi.

👉 [Miabi](https://github.com/miabi-io/miabi) ·
[Miabi architecture](https://docs.miabi.io/docs/architecture/overview)

---

## External Providers

### Docker / Swarm

Use the external Docker provider for container-based environments.

👉 [Goma Docker Provider](https://github.com/jkaninda/goma-docker-provider)

---

### HTTP API Provider

Expose a REST API for dynamic configuration management.

Ideal for:

* Internal platforms
* Automation workflows
* Custom control planes

👉 [Goma HTTP Provider](https://github.com/jkaninda/goma-http-provider)

---

## Summary

Providers are a core building block of Goma Gateway:

* They enable **automation**
* They support **modern deployment models**
* They decouple **configuration from runtime**

For advanced setups, combine:

* **Git Provider** → GitOps
* **HTTP Provider** → centralized control
* **Goma Admin** → full control plane experience

For a production example of these pieces working together, see how
[Miabi](#miabi-paas-control-plane) drives the gateway with the File provider
locally and the HTTP provider across clusters.

```
