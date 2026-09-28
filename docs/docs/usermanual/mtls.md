---
title: Mutual TLS (mTLS)
sidebar_label: Mutual TLS (mTLS)
sidebar_position: 9
---


# Mutual TLS (mTLS)

Goma Gateway supports **Mutual TLS (mTLS)** for both **outbound connections to backend services** and **inbound connections from external clients**.

mTLS enforces **two-way certificate validation**, ensuring both parties cryptographically authenticate each other before exchanging application data.

---

## 1. Backend mTLS (Gateway as Client)

When forwarding requests to upstream services, Goma Gateway can operate as a **TLS client** establishing an mTLS connection to backend servers.

### TLS Handshake Overview

```mermaid
sequenceDiagram
    participant Client as Goma Gateway
    participant Server as Backend Service

    Client->>Server: ClientHello
    Server->>Client: Server Certificate + CertificateRequest
    Client->>Client: Verify server certificate (rootCAs)
    Client->>Server: Client Certificate + CertificateVerify
    Server->>Server: Verify client certificate
    Client->>Server: Application Request
    Server->>Client: Response
```

During this exchange, the gateway:

* Validates the backend’s certificate (**server authentication**)
* Presents its own client certificate (**client authentication**)

This ensures only trusted gateways can communicate with secured backend services.

---

## 2. Client mTLS (Gateway as Server)

Goma Gateway can also accept inbound connections from external clients over mTLS, requiring them to present trusted certificates.

### TLS Handshake Overview

```mermaid
sequenceDiagram
    participant Client as External Client
    participant Gateway as Goma Gateway

    Client->>Gateway: ClientHello
    Gateway->>Client: Server Certificate + CertificateRequest
    Client->>Client: Verify server certificate
    Client->>Gateway: Client Certificate + CertificateVerify
    Gateway->>Gateway: Verify client certificate (clientCA)
    Client->>Gateway: Application Request
    Gateway->>Client: Response
```

### Configuration Example

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

Client authentication is configured once for the gateway and applies to every HTTPS connection on the `webSecure` entry point.

| Field      | Default | Description                                                                                                                  |
|------------|---------|------------------------------------------------------------------------------------------------------------------------------|
| `clientCA` | —       | CA certificate(s) used to verify client certificates. Accepts a file path, raw PEM, or base64-encoded PEM.                   |
| `required` | `false` | `true`: the handshake fails unless the client presents a certificate signed by `clientCA`. `false`: a certificate is optional, but one that is presented must verify. |

:::note
If `clientCA` cannot be loaded, the gateway refuses to start. A reload with an
unloadable `clientCA` is rejected and the gateway keeps its previous configuration.
:::

### Flow Summary

1. Client authenticates the gateway
2. Gateway authenticates the client
3. Traffic proceeds only if both validations succeed

---

## Architecture Overview

```mermaid
flowchart LR
    subgraph External
        C1[External Client]
    end

    subgraph Gateway[Goma Gateway]
        direction TB
        S1[mTLS Server Mode]
        S2[mTLS Client Mode]
    end

    subgraph Backend
        B1[Protected Service]
    end

    C1 -- mTLS --> S1
    S2 -- mTLS --> B1
```

---

## How Mutual TLS Works?

Standard TLS provides **server-side authentication only** — Goma Gateway verifies the backend certificate.

With **Mutual TLS**, authentication becomes **bidirectional**:

```
Client → verifies → Server certificate
Server → verifies → Client certificate
```

Benefits include:

* Strong identity enforcement
* Zero-trust compatible service communication
* Reduced surface for unauthorized access

---

## Backend Configuration

Backend mTLS is configured per route through its `security.tls` section, and applies to every backend of that route and to its health checks.

| Field                | Required | Description                                                                            |
|----------------------|----------|----------------------------------------------------------------------------------------|
| `rootCAs`            | Yes      | CA certificate used to validate backend certificates. Supports path, PEM, or base64.   |
| `clientCert`         | Yes      | Client certificate presented by the gateway. Supports path, PEM, or base64.            |
| `clientKey`          | Yes      | Private key corresponding to `clientCert`. Supports path, PEM, or base64.              |
| `insecureSkipVerify` | No       | Disables certificate verification. Default: `false`. Use only for development/testing. |

> **Note:** All certificate fields (`rootCAs`, `clientCert`, `clientKey`) accept:
>
> * File paths
> * Raw PEM content
> * Base64-encoded PEM

:::note
`rootCAs`, `clientCert`, and `clientKey` are only used together. If one of them is
missing, none is loaded: the gateway presents no client certificate and verifies
the backend against the system trust store. When they are set, `rootCAs`
replaces the system trust store for that route.
:::

---

## Example: Backend mTLS Routing

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





