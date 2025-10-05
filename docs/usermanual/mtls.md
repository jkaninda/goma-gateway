---
title: Mutual TLS (mTLS)
layout: default
parent: User Manual
nav_order: 9
---


# Mutual TLS (mTLS)

Goma Gateway supports **Mutual TLS (mTLS)** authentication **when connecting to backend services**.
In this mode, Goma Gateway acts as the **client**, authenticating itself to the backend server using a client certificate while also verifying the backend’s certificate for authenticity.

> **Note:**
> Goma Gateway does **not** support accepting inbound mTLS connections from external clients.
> mTLS is only applied **between Goma Gateway and upstream backends**.

---

## How It Works

In a typical TLS connection, Goma Gateway verifies the backend server’s certificate to ensure it’s trusted.
With **Mutual TLS**, the backend server also verifies Goma Gateway’s client certificate, enabling **two-way trust**.
This setup ensures that only authenticated gateways can communicate with your backend services.

---

## Configuration

You can enable mTLS per route by defining the `security.tls` section under each backend configuration.

| Field                | Required | Description                                                                                               |
|----------------------|----------|-----------------------------------------------------------------------------------------------------------|
| `rootCAs`            | Yes      | Path to the CA certificate file (or inline PEM/base64) used to verify the backend’s certificate.          |
| `clientCert`         | Yes      | Path or content of the client certificate presented by Goma Gateway to the backend.                       |
| `clientKey`          | Yes      | Path or content of the private key corresponding to the client certificate.                               |
| `insecureSkipVerify` | No       | Set to `false` to enforce strict certificate verification. Set to `true` only for development or testing. |

> **Note:**
> All fields (`rootCAs`, `clientCert`, `clientKey`) support **file paths**, **raw PEM content**, or **base64-encoded strings**.

---

## Example: Backend mTLS Configuration

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


