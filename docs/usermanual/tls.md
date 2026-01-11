---
title: TLS & Let's Encrypt
layout: default
parent: User Manual
nav_order: 8
---

# TLS & Let's Encrypt Configuration

Goma Gateway supports TLS encryption for securing traffic between clients and the gateway. You can configure TLS certificates manually or automatically using Let's Encrypt (ACME).

---

## **Manual TLS Configuration**
Define global TLS certificates for your routes by specifying certificate and private key pairs.

### **Configuration Keys**

| Key        | Type     | Description                                                                                                                                |
|------------|----------|--------------------------------------------------------------------------------------------------------------------------------------------|
| **`cert`** | `string` | TLS certificate, provided as:<ul><li>File path (e.g., `/path/to/cert.crt`)</li><li>Raw PEM content</li><li>Base64-encoded string</li></ul> |
| **`key`**  | `string` | Private key, provided as:<ul><li>File path (e.g., `/path/to/key.pem`)</li><li>Raw PEM content</li><li>Base64-encoded string</li></ul>      |


### **Example**
```yaml
version: 2
gateway:
  tls:
    #keys: tls.keys is deprecated since v0.7.0, please use certificates
    certificates:
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
    - path: /
      name: secure-route2
      hosts: ["api.example.com"]
      backends:
        - endpoint: https://backend.example.com
```

---

## **Automatic Certificates with Let's Encrypt (ACME)**
Goma Gateway supports ACME providers like Let's Encrypt for automatic certificate issuance and renewal.

> Volume: Certificates and related data are stored in the container under /etc/letsencrypt.


### **Basic Configuration**

To enable automatic certificate management, define at least the email for your ACME account and ensure the gateway is listening on ports 80 (for HTTP-01 challenges) and 443 (for HTTPS).

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"    # Required for HTTP-01 challenge
    webSecure:
      address: ":443"   # HTTPS endpoint
  routes: []            # Define routes as needed

certManager:
  acme:
    email: "admin@example.com"  # Email used for ACME registration and expiry notices
```
### **Advanced Configuration**

The `CertificateManager` block supports further customization:


| Key                | Description                                                                                                |
|--------------------|------------------------------------------------------------------------------------------------------------|
| **`directoryURL`** | Custom ACME directory, for example:<br><code>https://acme-staging-v02.api.letsencrypt.org/directory</code> |
| **`storageFile`**  | File to store ACME certificates (default: <code>acme.json</code>)                                          |
| **`challenge`**    | Challenge type (<code>http-01</code> or <code>dns-01</code>) and DNS provider (e.g., cloudflare, acme)     |
| **`credentials`**  | Provider-specific credentials (e.g., API tokens)                                                           |


#### **Example (DNS-01 Challenge with Cloudflare)**
```yaml
certManager:
  provider: acme
  acme:
    email: "admin@example.com"
    directoryUrl: "https://acme-staging-v02.api.letsencrypt.org/directory"
    storageFile: "acme.json"
    challengeType: dns-01
    dnsProvider: cloudflare
    credentials:
      apiToken: xxx-xxx-xxx
```

---