---
title: TLS Certificate
layout: default
parent: User Manual
nav_order: 7
---


## TLS Configuration

Goma Gateway allows you to define global TLS certificates for securing routes.

These certificates are used to encrypt traffic between clients and the gateway.

#### Keys Configuration

You can define a list of TLS certificates for the routes using the following keys:

- **`cert`** (`string`):  
  Specifies the TLS certificate. This can be provided as:
    - A file path to the certificate.
    - Raw certificate content.
    - A base64-encoded certificate.

- **`key`** (`string`):  
  Specifies the private key corresponding to the TLS certificate. This can be provided as:
    - A file path to the private key.
    - Raw private key content.
    - A base64-encoded private key.

---

### Example Configuration

Below is an example of how to configure global TLS certificates for your routes:

```yaml
version: 2
gateway:
  tls:  # Global TLS configuration for the gateway
    keys:  # List of TLS certificates and private keys
      - cert: /path/to/certificate.crt  # File path to the TLS certificate
        key: /path/to/private.key  # File path to the private key
      - cert: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...  # Base64-encoded certificate
        key:  LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...  # Base64-encoded private key
      - cert: |  # Raw certificate content (PEM format)
          -----BEGIN CERTIFICATE-----
            <certificate content>
          -----END CERTIFICATE-----
        key: |  # Raw private key content (PEM format)
          -----BEGIN PRIVATE KEY-----
             <private-key content>
          -----END PRIVATE KEY-----
  routes:
    - path: /
      name: secure route
      hosts:
        - example.com
      rewrite: /
      methods: []
      backends:
        - endpoint: https://backend.example.com
      cors: {}
```