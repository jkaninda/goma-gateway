---
title: TLS Certificate
layout: default
parent: User Manual
nav_order: 7
---


# TLS Certificate

Goma Gateway supports TLS to ensure secure communication between clients and the gateway.


## Configuration Example

To enable TLS, specify the certificate and private key file paths in your configuration file:

```yaml
version: 1.0
gateway:
  tlsCertFile: cert.pem  # Path to the TLS certificate file.
  tlsKeyFile: key.pem    # Path to the TLS private key file.
```

