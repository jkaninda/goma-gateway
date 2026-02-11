---
title: TLS & Let's Encrypt
layout: default
parent: User Manual
nav_order: 8
---

# TLS & Let's Encrypt Configuration

Goma Gateway supports TLS encryption for securing traffic between clients and the gateway. You can configure TLS certificates in three ways:

- **Manual configuration** — Provide your own certificate and key files
- **Directory-based loading** — Load multiple certificates from a directory
- **Automatic management** — Use Let's Encrypt (ACME) for automatic issuance and renewal

---

## Manual TLS Configuration

Define TLS certificates globally or per-route by specifying certificate and private key pairs.

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

### Route-Level Configuration

You can also specify TLS certificates for individual routes:

```yaml
version: 2
gateway:
  routes:
    - path: /
      name: secure-route
      hosts: ["example.com"]
      backends:
        - endpoint: https://backend.example.com
      tls:
        certificates:
          - cert: /path/to/route-specific-cert.crt
            key: /path/to/route-specific-key.key
```

> **Note:** Route-level certificates take precedence over global certificates for matching hosts.

---

## Directory-Based Certificate Loading

Load multiple certificates from a single directory. Goma matches certificate and key files by filename.

### Requirements

- Certificate and key files must share the same base name
- **Certificate extensions:** `.crt`, `.cert`, `.pem`
- **Key extension:** `.key`

### Configuration

```yaml
version: 2
gateway:
  tls:
    certDir: /etc/goma/certs
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

## Automatic Certificates with Let's Encrypt (ACME)

Goma Gateway supports automatic certificate issuance and renewal using ACME providers like Let's Encrypt.

### Prerequisites

- Domain must be publicly accessible
- Port 80 must be available for HTTP-01 challenges (or configure DNS-01)
- Valid email address for ACME registration

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
  provider: acme
  acme:
    email: "admin@example.com"
```

> **Storage:** Certificates and ACME account data are stored in `/etc/letsencrypt` by default. Mount this as a persistent volume in containerized deployments.

### Configuration Options

| Key             | Type   | Description                                                       |
|-----------------|--------|-------------------------------------------------------------------|
| `email`         | string | **Required.** Email for ACME registration and expiry notices      |
| `directoryUrl`  | string | ACME directory URL. Default: Let's Encrypt production             |
| `storageFile`   | string | File to store certificates. Default: `acme.json`                  |
| `challengeType` | string | `http-01` (default) or `dns-01`                                   |
| `dnsProvider`   | string | DNS provider for DNS-01 challenge (e.g., `cloudflare`, `route53`) |
| `credentials`   | object | Provider-specific credentials                                     |

### DNS-01 Challenge (Cloudflare Example)

Use DNS-01 when port 80 is unavailable or for wildcard certificates:

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
  provider: acme
  acme:
    email: "admin@example.com"
    challengeType: dns-01
    dnsProvider: cloudflare
    credentials:
      apiToken: your-cloudflare-api-token
```

### Using the Staging Environment

For testing, use Let's Encrypt's staging environment to avoid rate limits:

```yaml
certManager:
  provider: acme
  acme:
    email: "admin@example.com"
    directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory"
```

> **Warning:** Staging certificates are not trusted by browsers. Switch to production (`https://acme-v02.api.letsencrypt.org/directory`) for live deployments.

---

## Troubleshooting

### Certificate Not Found

Ensure the hostname in your route's `hosts` field matches the certificate's Common Name (CN) or Subject Alternative Names (SANs).

### ACME Challenge Failures

- **HTTP-01:** Verify port 80 is accessible and not blocked by firewalls
- **DNS-01:** Check that API credentials have permission to create TXT records

### Certificate Renewal

ACME certificates are automatically renewed before expiration. Ensure the `/etc/letsencrypt` directory is persistent across container restarts.