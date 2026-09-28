---
title: TLS & Let's Encrypt
sidebar_label: TLS & Let's Encrypt
sidebar_position: 8
---

# TLS & Let's Encrypt Configuration

Goma Gateway terminates TLS for every route served on the `webSecure` entry point. Certificates come from one of three sources:

- **Manual configuration** — provide your own certificate and key, globally or per route
- **Directory-based loading** — load many certificates from one directory
- **Automatic management** — let CertManager issue and renew certificates from an ACME CA (Let's Encrypt, ZeroSSL, [Certio](#private-ca-with-certio), …) or a HashiCorp Vault PKI

For each TLS handshake, the gateway selects a certificate by the requested hostname (SNI):

1. A custom certificate that names the host exactly — route `tls.certificate` first, then `gateway.tls.certificates`, then `certsDir`
2. Otherwise, the most specific match among custom and CertManager-issued certificates (an exact name beats a wildcard)
3. Otherwise, `gateway.tls.default`, or a generated self-signed certificate if none is configured

When no certificate names the host exactly and a CertManager provider is responsible for it, the gateway orders one in the background and serves the best available certificate meanwhile.

:::info[Upgrading from v0.x]

v1.0 removed the TLS keys deprecated during v0.x. A configuration that still uses them will not start:

| Removed (v0.x)            | Use in v1.0                   |
|---------------------------|-------------------------------|
| `certificateManager`      | `certManager`                 |
| `gateway.tls.keys`        | `gateway.tls.certificates`    |

Run `goma config check` to list every removed key in your configuration. See the [v1.0 upgrade notes](../upgrade/v1.0.md).

:::

---

## Manual TLS Configuration

### Certificate Formats

Certificates and keys can be provided in any of these formats:

| Format          | Example                          |
|-----------------|----------------------------------|
| File path       | `/path/to/cert.crt`              |
| Base64-encoded  | `LS0tLS1CRUdJTi...`              |
| Raw PEM content | `-----BEGIN CERTIFICATE-----...` |

### Global Configuration

```yaml
version: 2
gateway:
  tls:
    certificates:
      # File paths
      - cert: /path/to/certificate.crt
        key: /path/to/private.key

      # Base64-encoded
      - cert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...
        key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t...

      # Raw PEM content
      - cert: |
          -----BEGIN CERTIFICATE-----
          <certificate content>
          -----END CERTIFICATE-----
        key: |
          -----BEGIN PRIVATE KEY-----
          <private key content>
          -----END PRIVATE KEY-----

    # Fallback certificate for unmatched hosts
    default:
      cert: /etc/goma/default-cert.pem
      key: /etc/goma/default-key.pem

  routes:
    - path: /
      name: secure-route
      hosts: ["example.com"]
      backends:
        - endpoint: https://backend.example.com
```

`gateway.tls.clientAuth` enables client certificate verification; see [Mutual TLS (mTLS)](./mtls.md).

### Route-Level Configuration

A route can carry its own certificate under `tls.certificate` — a single `cert`/`key` pair covering the route's hosts:

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: secure-route
      hosts: ["example.com", "www.example.com"]
      backends:
        - endpoint: https://backend.example.com
      tls:
        provider: none          # don't ask CertManager for a certificate
        certificate:
          cert: /etc/goma/certs/example.com-fullchain.pem
          key: /etc/goma/certs/example.com.key
```

When the same host has more than one custom certificate, a route's `tls.certificate` wins over `gateway.tls.certificates`, which wins over `certsDir`. Within `certsDir`, files are loaded in filename order and the last one for a host wins. Set `provider: none` when a CertManager provider is configured, so it doesn't also request a certificate for these hosts.

> **Note:** v1.0 uses `tls.certificate` (one pair) on routes. A `tls.certificates` list is only valid under `gateway.tls`.

---

## Directory-Based Certificate Loading

Load multiple certificates from a single directory (default: `/etc/goma/certs`). Goma matches certificate and key files by filename.

### Requirements

- Certificate and key files must share the same base name
- **Certificate extensions:** `.crt`, `.cert`, `.pem`
- **Key extension:** `.key`

### Configuration

```yaml
version: 2
gateway:
  tls:
    certsDir: /etc/goma/certs
```

### Example Directory Structure

```
/etc/goma/certs/
├── example.com.crt       # Paired with example.com.key
├── example.com.key
├── api.example.com.crt   # Paired with api.example.com.key
├── api.example.com.key
├── wildcard.crt          # Paired with wildcard.key
└── wildcard.key
```

---

## Automatic Certificates (CertManager)

`certManager` issues and renews certificates for route hosts automatically. You declare one or more **named providers**, each of `type: acme` or `type: vault`, and choose which one serves each route.

```yaml
certManager:
  defaultProvider: letsencrypt       # used by routes without tls.provider
  providers:
    letsencrypt:
      type: acme
      acme:
        email: "admin@example.com"
```

When only one provider is defined, it becomes the default automatically.

**Renewal:** CertManager checks certificates every 6 hours and renews any that expire within 30 days.

**Storage:** certificates and ACME account data are stored under `/etc/letsencrypt` (see [Storage layout](#storage-layout)). Mount it as a persistent volume in containerized deployments, or every restart re-issues certificates and burns CA rate limits.

---

## ACME (Let's Encrypt and other CAs)

### Prerequisites

- A valid email address — `email` is required for every ACME provider
- For **HTTP-01**: the domain resolves to the gateway and the `web` entry point is reachable by the CA on port 80
- For **DNS-01**: an API token for a supported DNS provider

### Basic Configuration (HTTP-01 Challenge)

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"      # Required for HTTP-01 challenge
    webSecure:
      address: ":443"     # HTTPS endpoint
  routes:
    - path: /
      name: my-app
      hosts: ["example.com"]
      backends:
        - endpoint: http://localhost:8080

certManager:
  defaultProvider: letsencrypt
  providers:
    letsencrypt:
      type: acme
      acme:
        email: "admin@example.com"
```

The gateway answers `/.well-known/acme-challenge/` requests on the `web` entry point itself; no other port needs to be exposed.

### Configuration Options

| Key                  | Type   | Description                                                                                        |
|----------------------|--------|----------------------------------------------------------------------------------------------------|
| `email`              | string | **Required.** Email for ACME registration and expiry notices                                       |
| `directoryUrl`       | string | ACME directory URL. Default: Let's Encrypt production                                              |
| `challengeType`      | string | `http-01` (default) or `dns-01`                                                                    |
| `dnsProvider`        | string | DNS provider for DNS-01. Supported: `cloudflare`                                                   |
| `credentials`        | object | DNS provider credentials: `apiToken` (or the `GOMA_CREDENTIALS_API_TOKEN` environment variable)    |
| `eab`                | object | External account binding: `kid` and `hmacKey` (see [below](#external-account-binding-eab))         |
| `storageFile`        | string | File to store certificates and the account. Default: `/etc/letsencrypt/acme-<provider-name>.json`  |
| `termsAccepted`      | bool   | Agreement to the CA's terms. Omitted means agreed                                                  |
| `insecureSkipVerify` | bool   | Skip TLS verification of the ACME directory. Prefer [trusting the CA](#3-trust-certios-root-ca)      |

### DNS-01 Challenge

Use DNS-01 when port 80 is unavailable or for wildcard certificates. Cloudflare is currently the only supported DNS provider.

```yaml
version: 2
gateway:
  entryPoints:
    webSecure:
      address: ":443"
  routes:
    - path: /
      name: my-app
      hosts: ["*.example.com", "example.com"]
      backends:
        - endpoint: http://localhost:8080

certManager:
  defaultProvider: cloudflare-dns
  providers:
    cloudflare-dns:
      type: acme
      acme:
        email: "admin@example.com"
        challengeType: dns-01
        dnsProvider: cloudflare
        credentials:
          apiToken: "${CLOUDFLARE_API_TOKEN}"
```

The token needs permission to edit DNS records (`Zone.DNS:Edit`) for the zone.

### Using the Staging Environment

For testing, use Let's Encrypt's staging environment to avoid rate limits:

```yaml
certManager:
  providers:
    letsencrypt-staging:
      type: acme
      acme:
        email: "admin@example.com"
        directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory"
```

> **Warning:** Staging certificates are not trusted by browsers. Switch to production (`https://acme-v02.api.letsencrypt.org/directory`) for live deployments.

### External Account Binding (EAB)

Let's Encrypt issues to anyone who can answer a challenge, but most other CAs — ZeroSSL, Google Public CA, Sectigo, Certio, and other private CAs — first want to know *which* of their subscribers is asking. They hand you a key id and an HMAC key out of band; the gateway proves it holds that key when it registers its ACME account, and the CA ties the account to whatever it authorized the credential for.

```yaml
certManager:
  providers:
    zerossl:
      type: acme
      acme:
        email: "admin@example.com"
        directoryUrl: "https://acme.zerossl.com/v2/DV90"
        eab:
          kid: "your-key-id"
          hmacKey: "${GOMA_ACME_EAB_HMAC}"
```

Every field in the config file expands `${VAR}` from the environment, so keep the HMAC key out of the file and pass it as `GOMA_ACME_EAB_HMAC` (any name works). `hmacKey` is base64url-encoded, exactly the value other ACME clients take in their `--eab-hmac-key` flag.

A few things worth knowing:

- **Both fields or neither.** Setting only one fails at startup rather than at registration.
- **A directory that requires a binding says so.** If the ACME directory advertises `externalAccountRequired` and no `eab` block is configured, the provider fails with a message naming the two fields instead of the CA's error later on.
- **Rotating the credential registers a new account.** A CA checks the binding only when an account is created, so an existing account key stays bound to the credential it registered with. Changing `kid` therefore makes the gateway generate a new account key and register again under the new credential. Certificates already in the store keep working and are renewed through the new account. Changing only `hmacKey` — the same credential with a re-issued secret — does not re-register.

---

## Private CA with Certio

[Certio](https://github.com/jkaninda/certio) is a self-hosted private CA with a built-in ACME server. Pointing an ACME provider at it gives internal services the same automatic issuance and renewal as Let's Encrypt, with certificates signed by your own CA — no public DNS or internet exposure required.

### 1. Enable Certio's ACME server

Run Certio with ACME enabled and pick the CA that signs ACME orders (a name-constrained intermediate is the recommended choice):

```yaml
services:
  certio:
    image: jkaninda/certio:latest
    environment:
      CERTIO_BASE_URL: https://certio.corp.example.com
      CERTIO_MASTER_KEY: ${CERTIO_MASTER_KEY}
      CERTIO_JWT_SECRET: ${CERTIO_JWT_SECRET}
      CERTIO_ACME_ENABLED: "true"
      CERTIO_ACME_AUTHORITY: internal-issuing-ca
    volumes:
      - certio_data:/data

volumes:
  certio_data: {}
```

The ACME directory is served at `<CERTIO_BASE_URL>/acme/directory`.

### 2. Create an EAB credential

Certio requires external account binding by default. Create a credential in the dashboard (**Settings → ACME**) or via the API, limited to the domains the gateway should get certificates for:

```bash
curl -X POST https://certio.corp.example.com/api/v1/acme/external-accounts \
     -H "Authorization: Bearer certio_…" \
     -d '{"description":"goma gateway","allowed_domains":["corp.example.com"]}'
```

The response contains the `kid` and `hmac` to put in the gateway configuration.

### 3. Trust Certio's root CA

If Certio itself is served over HTTPS with a certificate from your private CA, the gateway must trust that CA to reach the ACME directory. Export the root certificate:

```bash
certio ca export <root-ca-name> -o ./trust
```

Mount the exported PEM into the gateway and add its directory to `SSL_CERT_DIR`. The system CA bundle is still loaded, so public CAs such as Let's Encrypt keep working:

```yaml
  goma-gateway:
    image: jkaninda/goma-gateway:latest
    environment:
      SSL_CERT_DIR: /etc/goma/trust
      GOMA_CERTIO_EAB_HMAC: ${GOMA_CERTIO_EAB_HMAC}
    volumes:
      - ./config:/etc/goma
      - ./trust:/etc/goma/trust:ro
      - ./letsencrypt:/etc/letsencrypt
```

`acme.insecureSkipVerify: true` also works, but it disables verification of the CA you are trusting to issue your certificates — use it only for local testing.

### 4. Configure the provider

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: internal-api
      hosts: ["api.corp.example.com"]
      tls:
        provider: certio
      backends:
        - endpoint: http://api:8080

certManager:
  providers:
    certio:
      type: acme
      acme:
        email: "platform@corp.example.com"
        directoryUrl: https://certio.corp.example.com/acme/directory
        challengeType: http-01
        eab:
          kid: "<kid>"
          hmacKey: "${GOMA_CERTIO_EAB_HMAC}"
```

For HTTP-01, Certio must be able to reach `api.corp.example.com` on port 80 through the gateway's `web` entry point. Wildcard hosts need `dns-01`, which Certio requires for wildcards.

Clients calling these routes must trust Certio's root CA as well — distribute it the same way as any other internal root (OS trust store, Kubernetes `ConfigMap`, MDM, …).

> **Static certificates instead of ACME:** Certio can also export issued certificates as Goma config snippets (`--format goma` for `gateway.tls.certificates`, `--format goma-route` for a route's `tls.certificate`). Use those when you prefer to manage renewal outside the gateway.

---

## HashiCorp Vault (PKI)

Goma Gateway can issue and renew certificates directly from a [HashiCorp Vault PKI secrets engine](https://developer.hashicorp.com/vault/docs/secrets/pki) instead of ACME. This is useful for internal services and private PKI where certificates are signed by your own CA rather than a public authority — no ACME challenge, no inbound port 80, and no public DNS required.

### Prerequisites

- A reachable Vault server with the PKI secrets engine enabled (default mount `pki`).
- A PKI **role** that permits the domains you intend to issue for.
- A Vault **token** with permission to call `pki/issue/<role>`.

### Basic Configuration

```yaml
version: 2
gateway:
  entryPoints:
    webSecure:
      address: ":443"
  routes:
    - path: /
      name: internal-app
      hosts: ["app.internal"]
      backends:
        - endpoint: http://localhost:8080

certManager:
  defaultProvider: vault
  providers:
    vault:
      type: vault
      vault:
        address: https://vault.example.com   # or set VAULT_ADDR
        token: ""                             # prefer the VAULT_TOKEN env var
        role: goma-gateway
```

> **Credentials:** Prefer the standard `VAULT_ADDR` and `VAULT_TOKEN` environment variables over inlining them in the config file. When set, they take precedence over the `address` / `token` fields.

### Configuration Options

| Key                  | Type   | Description                                                                                       |
|----------------------|--------|---------------------------------------------------------------------------------------------------|
| `address`            | string | **Required.** Vault base URL (e.g. `https://vault.example.com`). Falls back to `VAULT_ADDR`.      |
| `token`              | string | **Required.** Vault token. Falls back to `VAULT_TOKEN`. Prefer the env var over the config file.  |
| `role`               | string | **Required.** PKI role used to issue certificates (`pki/issue/<role>`).                           |
| `mount`              | string | PKI secrets engine mount path. Default: `pki`.                                                    |
| `namespace`          | string | Vault Enterprise namespace. Falls back to `VAULT_NAMESPACE`.                                      |
| `ttl`                | string | Requested certificate lifetime (e.g. `72h`). Default: the PKI role's TTL.                         |
| `storageFile`        | string | File to persist issued certificates. Default: `/etc/letsencrypt/vault-<provider-name>.json`.      |
| `insecureSkipVerify` | bool   | Skip TLS verification of the Vault server. Prefer trusting its CA via `SSL_CERT_DIR`.             |

### How It Works

For each route host, Goma calls `POST <address>/v1/<mount>/issue/<role>` with the host as the common name (additional hosts become SANs) and serves the returned leaf certificate together with its issuing CA chain. Certificates are cached to disk and renewed on the same schedule as ACME certificates.

> **Short-lived certificates:** Vault PKI certificates often have short TTLs. Goma renews any certificate within 30 days of expiry, so a certificate with a TTL under 30 days is reissued on each renewal cycle (every 6 hours). This is expected.

---

## Per-Route Provider Selection

The `tls.provider` field on a Route controls which provider issues its certificates.

| Value             | Meaning                                                                                              |
|-------------------|------------------------------------------------------------------------------------------------------|
| _unset_ / `""`    | Use `certManager.defaultProvider`.                                                                   |
| `none`            | Opt out — CertManager never requests a cert for this route. Falls back to custom or default cert.    |
| `<provider-name>` | Use the named provider from `certManager.providers`.                                                 |

### Excluding a Route (`tls.provider: none`)

Some routes shouldn't be issued certs by CertManager — TLS is terminated upstream (Cloudflare, a load balancer), the host isn't publicly resolvable, or you've already provided a route-level certificate. Requesting certificates for those hosts wastes ACME quota and can get your account temporarily banned for repeated failed challenges.

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: behind-cloudflare
      hosts: ["app.example.com"]
      tls:
        provider: none       # CertManager will not request a cert for this route
      backends:
        - endpoint: http://localhost:8080

certManager:
  providers:
    letsencrypt:
      type: acme
      acme:
        email: "admin@example.com"
```

When `tls.provider: none` is set, the route's hosts are never registered with CertManager. Incoming TLS connections are served, in order:

1. A matching custom certificate (route `tls.certificate`, `gateway.tls.certificates`, or `certsDir`)
2. The gateway's default certificate

### Unknown Provider Names

If a Route's `tls.provider` doesn't match any name in `certManager.providers` (and isn't `""` or `none`), the gateway logs a warning and uses `defaultProvider` for that route. If there is no default provider, it logs an error and disables certificate provisioning for the route, as if `provider: none` were set. Watch the startup logs for `Unknown tls.provider on route` after renaming a provider.

---

## Multiple Providers

Providers can be any mix of `type: acme` and `type: vault`. Common reasons to configure several:

- Public routes use Let's Encrypt while internal routes use a private CA (Certio or Vault).
- Some routes need DNS-01 (wildcards, no inbound port 80) while others use HTTP-01.
- Different routes belong to different ACME accounts (separate Let's Encrypt rate-limit pools).
- One environment uses Let's Encrypt staging while another uses production.

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: api
      hosts: ["api.example.com"]
      tls:
        provider: cloudflare-dns         # DNS-01 with Cloudflare
      backends:
        - endpoint: http://localhost:8080

    - path: /
      name: marketing
      hosts: ["marketing.example.com"]   # tls.provider unset → defaultProvider
      backends:
        - endpoint: http://localhost:8081

    - path: /
      name: staging-app
      hosts: ["staging.example.com"]
      tls:
        provider: letsencrypt-staging    # Let's Encrypt staging directory
      backends:
        - endpoint: http://localhost:8082

    - path: /
      name: internal-api
      hosts: ["api.corp.example.com"]
      tls:
        provider: certio                 # private CA over ACME
      backends:
        - endpoint: http://localhost:8083

    - path: /
      name: internal-admin
      hosts: ["admin.internal"]
      tls:
        provider: vault                  # private PKI via Vault
      backends:
        - endpoint: http://localhost:8084

certManager:
  defaultProvider: letsencrypt
  providers:
    letsencrypt:
      type: acme
      acme:
        email: "ops@example.com"
        challengeType: http-01

    letsencrypt-staging:
      type: acme
      acme:
        email: "ops@example.com"
        directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory"

    cloudflare-dns:
      type: acme
      acme:
        email: "ops@example.com"
        challengeType: dns-01
        dnsProvider: cloudflare
        credentials:
          apiToken: "${CLOUDFLARE_API_TOKEN}"

    certio:
      type: acme
      acme:
        email: "ops@example.com"
        directoryUrl: "https://certio.corp.example.com/acme/directory"
        eab:
          kid: "<kid>"
          hmacKey: "${GOMA_CERTIO_EAB_HMAC}"

    vault:
      type: vault
      vault:
        address: https://vault.example.com   # or set VAULT_ADDR
        token: ""                             # prefer the VAULT_TOKEN env var
        role: goma-gateway
```

### Storage Layout

Each provider keeps its own certificate cache (and, for ACME, its own account) under `/etc/letsencrypt/`:

- ACME providers default to `acme-<provider-name>.json` (e.g. `acme-letsencrypt.json`, `acme-certio.json`).
- Vault providers default to `vault-<provider-name>.json`.
- Override per provider via `acme.storageFile` or `vault.storageFile`.

> **Important:** in containerized deployments, mount `/etc/letsencrypt/` (or your custom path) as a persistent volume. Sharing one storage file between providers will corrupt ACME account state.

### Single-Provider Shorthand

The shorter single-provider form is still accepted:

```yaml
certManager:
  provider: acme
  acme:
    email: "admin@example.com"
```

At load time it becomes a provider named `default` (stored in `acme.json`) and is set as `defaultProvider`. New configurations should use `providers`, which makes adding a second provider later a non-breaking change.

---

## Troubleshooting

### Certificate Not Found

Ensure the hostname in your route's `hosts` field matches the certificate's Common Name (CN) or Subject Alternative Names (SANs).

### `no email address provided`

Every ACME provider needs `acme.email`, including private CAs such as Certio.

### ACME Challenge Failures

- **HTTP-01:** Verify the CA can reach the host on port 80 and that the `web` entry point listens there
- **DNS-01:** Check that the API token has permission to edit DNS records for the zone

### `x509: certificate signed by unknown authority`

The gateway doesn't trust the TLS certificate of the ACME directory or Vault server — typical with a private CA. Mount the CA certificate and point `SSL_CERT_DIR` at it, as shown in [Trust Certio's root CA](#3-trust-certios-root-ca).

### Certificate Renewal

Certificates are renewed automatically within 30 days of expiry. Ensure `/etc/letsencrypt` is persistent across container restarts.
