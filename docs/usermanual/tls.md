---
title: TLS & Let's Encrypt
layout: default
parent: User Manual
nav_order: 7
---

# TLS & Let's Encrypt Configuration

Goma Gateway supports TLS encryption for securing traffic between clients and the gateway. You can configure TLS certificates manually or automatically using Let's Encrypt (ACME).

---

## **Manual TLS Configuration**
Define global TLS certificates for your routes by specifying certificate and private key pairs.

### **Configuration Keys**
| Key        | Type     | Description                                                                                                              |
|------------|----------|--------------------------------------------------------------------------------------------------------------------------|
| **`cert`** | `string` | TLS certificate, provided as:<br>• File path (e.g., `/path/to/cert.crt`)<br>• Raw PEM content<br>• Base64-encoded string |
| **`key`**  | `string` | Private key, provided as:<br>• File path (e.g., `/path/to/key.pem`)<br>• Raw PEM content<br>• Base64-encoded string      |

### **Example**
```yaml
version: 2
gateway:
  tls:
    keys:
      # File paths
      - cert: /path/to/certificate.crt
        key: /path/to/private.key
      
      # Base64-encoded
      - cert: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...
        key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...
      
      # Raw PEM content
      - cert: |
          -----BEGIN CERTIFICATE-----
          <certificate content>
          -----END CERTIFICATE-----
        key: |
          -----BEGIN PRIVATE KEY-----
          <private-key content>
          -----END PRIVATE KEY-----
  routes:
    - path: /
      name: secure-route
      hosts: ["example.com"]
      backends:
        - endpoint: https://backend.example.com
```

---

## **Automatic Certificates with Let's Encrypt (ACME)**
Goma Gateway supports ACME providers like Let's Encrypt for automatic certificate issuance and renewal.

### **Basic Configuration**
```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"    # Required for HTTP-01 challenge
    webSecure:
      address: ":443"   # HTTPS endpoint
  routes: []            # Define routes as needed

acme:
  email: "admin@example.com"  # Required for Let's Encrypt account
```

### **Advanced Configuration**
| Key                | Description                                                                                                   |
|--------------------|---------------------------------------------------------------------------------------------------------------|
| **`directoryURL`** | Custom ACME directory (e.g., Let's Encrypt staging: `https://acme-staging-v02.api.letsencrypt.org/directory`) |
| **`storage`**      | File to store ACME certificates (default: `acme.json`)                                                        |
| **`challenge`**    | Challenge type (`http-01` or `dns-01`) and DNS provider (e.g., Cloudflare)                                    |
| **`credentials`**  | Provider-specific credentials (e.g., API tokens)                                                              |

#### **Example (DNS-01 Challenge with Cloudflare)**
```yaml
acme:
  email: "admin@example.com"
  directoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"
  storage: "acme.json"
  challenge:
    type: dns-01           # Use DNS challenge
    provider: cloudflare   # Supported DNS provider
  credentials:
    apiToken: "xxx-xxx-xxx" # Cloudflare API token
```

---