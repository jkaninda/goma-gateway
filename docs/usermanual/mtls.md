---
title: Mutual TLS (mTLS)
layout: default
parent: User Manual
nav_order: 9
---


# Mutual TLS (mTLS)

Goma Gateway supports **Mutual TLS (mTLS)** for both **outbound connections to backend services** and **inbound connections from external clients**.

mTLS enforces **two-way certificate verification**, ensuring that both parties are cryptographically authenticated before a connection is established.

---

## 1. Backend mTLS (Gateway as Client)

In this mode, Goma Gateway acts as a **TLS client** when forwarding requests to upstream services.

The gateway:

* Validates the backend service certificate (server authentication).
* Presents its own client certificate (client authentication).

This ensures only trusted gateways can reach protected backend services.

---

## 2. Client mTLS (Gateway as Server)

Goma Gateway can also **accept inbound mTLS connections**, requiring external clients to present trusted certificates.

Example:

```yaml
gateway:
  tls:
    certificates:
      - cert: /etc/goma/certs/cert.pem
        key: /etc/goma/certs/key.pem
    clientAuth:
      clientCA:  /etc/goma/certs/ca.pem
      required: true
```

When `required` is set to `true`, the connection is rejected unless the client presents a certificate signed by the defined CA.

---

## How Mutual TLS Works

Standard TLS provides **server-only authentication** — Goma Gateway verifies the backend certificate.

With **Mutual TLS**, authentication becomes bidirectional:

```
Client → verifies → Server certificate
Server → verifies → Client certificate
```

This provides:

* Strong identity verification
* Zero-trust friendly communication
* Reduced risk of unauthorized service access

---

## Backend Configuration

mTLS can be configured per-backend via the `security.tls` section on each route.

| Field                | Required | Description                                                                                     |
|----------------------|----------|-------------------------------------------------------------------------------------------------|
| `rootCAs`            | Yes      | CA certificate used to validate backend certificates. Accepts file path, inline PEM, or base64. |
| `clientCert`         | Yes      | Client certificate presented by the gateway. Supports path, PEM, or base64.                     |
| `clientKey`          | Yes      | Private key for `clientCert`. Supports path, PEM, or base64.                                    |
| `insecureSkipVerify` | No       | Disable certificate verification. Default: `false`. Use only for testing.                       |

> **Note:** All certificate fields (`rootCAs`, `clientCert`, `clientKey`) support:
>
> * File path
> * Raw PEM content
> * Base64-encoded PEM

---

## Example: Backend mTLS Connection

```yaml
routes:
  - name: api
    path: /
    hosts:
      - api.example.com
    enabled: true
    backends:
      - endpoint: https://api-example:8443
        weight: 80
      - endpoint: https://api-example-beta:8443
        weight: 20
    security:
      tls:
        insecureSkipVerify: false
        rootCAs: /etc/goma/certs/ca.pem
        clientCert: /etc/goma/certs/cert.pem
        clientKey: /etc/goma/certs/key.pem
    healthCheck:
      path: /
      interval: 15s
      timeout: 10s
      healthyStatuses: [200]
```



