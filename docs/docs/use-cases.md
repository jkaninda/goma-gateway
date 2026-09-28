---
title: Use Cases
sidebar_label: Use Cases
sidebar_position: 3
---

# Use Cases

Goma Gateway sits in front of your services and handles the concerns every one of them would otherwise re-implement: TLS, identity, abuse protection, routing, and observability. This page walks through the situations it is most often used for, each with a minimal configuration to start from.

Each snippet shows only the parts relevant to the use case. Combine them freely — they are all plain gateway configuration.

---

## Secure edge for public APIs

**The problem:** a public API needs HTTPS, authentication, and protection from abuse before a request ever reaches application code.

**With Goma:** certificates are issued and renewed automatically, JWTs are validated at the edge, and clients that exceed their rate limit are banned for a while. Backends only see authenticated, well-formed traffic.

```yaml
version: 2
gateway:
  routes:
    - name: public-api
      path: /
      hosts: ["api.example.com"]
      target: http://api:8080
      security:
        enableExploitProtection: true   # block common SQL injection and XSS patterns
      middlewares: ["jwt", "rate-limit", "body-limit"]

middlewares:
  - name: jwt
    type: jwtAuth
    paths: ["/.*"]
    rule:
      jwksUrl: https://auth.example.com/.well-known/jwks.json
      issuer: https://auth.example.com/
      audience: api.example.com
      forward:
        headers:
          X-User-ID: sub
  - name: rate-limit
    type: rateLimit
    rule:
      unit: minute
      requestsPerUnit: 120
      banAfter: 5
      banDuration: 10m
      keyStrategy:
        source: header
        name: X-API-Key
  - name: body-limit
    type: bodyLimit
    rule:
      limit: 2MiB

certManager:
  providers:
    letsencrypt:
      type: acme
      acme:
        email: ops@example.com
```

**See also:** [TLS & Let's Encrypt](./usermanual/tls.md), [JWT](./middlewares/jwt.md), [Rate Limiting](./middlewares/rate-limit.md), [Body Limit](./middlewares/body-limit.md)

---

## Single sign-on for internal tools and legacy apps

**The problem:** dashboards, admin panels, and older applications either have no login at all or their own password database, and you want them behind your company identity provider.

**With Goma:** the OpenID Connect middleware runs the login flow against Keycloak, Authentik, Okta, Google, or any other OIDC provider, keeps the session, and forwards the user's identity to the application as headers. The application needs no code changes.

```yaml
version: 2
gateway:
  routes:
    - name: grafana
      path: /
      hosts: ["grafana.corp.example.com"]
      target: http://grafana:3000
      middlewares: ["sso"]

middlewares:
  - name: sso
    type: oidc
    paths: ["/.*"]
    rule:
      issuer: https://sso.example.com/realms/corp
      clientId: goma
      clientSecret: ${OIDC_CLIENT_SECRET}
      scopes: [openid, email, profile]
      claimsExpression: "Contains('groups', 'engineering')"   # only this group gets in
      session:
        secret: ${SESSION_SECRET}
      forward:
        headers:
          X-User-Email: email
```

Already running an auth service such as Authelia or oauth2-proxy? Use [ForwardAuth](./middlewares/forward-auth.md) instead. Directory-backed setups can use [LDAP](./middlewares/ldap.md).

**See also:** [OpenID Connect](./middlewares/oidc.md), [ForwardAuth](./middlewares/forward-auth.md)

---

## Partner and B2B APIs with mutual TLS

**The problem:** a partner integration must be reachable only by known organizations, not by anyone holding a leaked API key.

**With Goma:** clients must present a certificate signed by your CA before the TLS handshake completes, and an access policy restricts traffic to the partners' network ranges.

```yaml
version: 2
gateway:
  tls:
    clientAuth:
      clientCA: /etc/goma/partners-ca.pem
      required: true
  routes:
    - name: partner-api
      path: /
      hosts: ["partners.example.com"]
      target: http://partner-api:8080
      middlewares: ["partner-networks"]

middlewares:
  - name: partner-networks
    type: accessPolicy
    rule:
      action: ALLOW
      sourceRanges:
        - 203.0.113.0/24
        - 198.51.100.17
```

Client certificate verification applies to the whole HTTPS entry point, so partner traffic is typically served by its own gateway instance.

**See also:** [Mutual TLS](./usermanual/mtls.md), [Access Policy](./middlewares/access-policy.md)

---

## API gateway for Kubernetes

**The problem:** services on Kubernetes need a gateway that is configured the same way as everything else in the cluster: declaratively, through the API server, and from Git.

**With Goma:** the [Kubernetes Operator](./operator-manual/index.md) deploys and scales gateways and manages routes and middleware as custom resources, and `/healthz` and `/readyz` plug into liveness and readiness probes.

```yaml
apiVersion: gateway.jkaninda.dev/v1alpha1
kind: Route
metadata:
  name: orders
spec:
  gateways: [gateway]
  path: /orders
  hosts: [api.example.com]
  target: http://orders.default.svc.cluster.local:8080
  middlewares: [api-rate-limit]
```

Run several replicas with Redis to share rate-limit counters and cache entries between them.

**See also:** [Operator Manual](./operator-manual/index.md), [Distributed Instances](./monitoring-and-performance/distributed-instances.md), [Health Checks](./usermanual/healthcheck.md)

---

## Edge for container platforms and self-hosted PaaS

**The problem:** a Docker host or internal platform runs many applications on many domains, and each new app should get a route and a certificate without anyone editing gateway configuration.

**With Goma:** [providers](./usermanual/providers.md) feed the gateway routes generated elsewhere — from container labels by [Goma Admin](https://github.com/jkaninda/goma-admin)'s Docker provider, or from your platform through the HTTP provider — and CertManager issues a certificate for every new host. [Miabi](https://github.com/miabi-io/miabi), a self-hosted PaaS, uses Goma Gateway as its edge layer this way.

```yaml
services:
  web:
    image: jkaninda/okapi-example
    labels:
      - "goma.enable=true"
      - "goma.port=8080"
      - "goma.hosts=app.example.com"
```

**See also:** [Providers](./usermanual/providers.md), [Goma Admin](https://github.com/jkaninda/goma-admin)

---

## Canary releases and targeted rollouts

**The problem:** a new version of a service should reach a small share of users, or only internal testers, before everyone.

**With Goma:** weighted backends shift a percentage of traffic to the new version, and match rules send specific users to it based on a header, cookie, query parameter, or IP. Health checks take a failing version out of rotation.

```yaml
version: 2
gateway:
  routes:
    - name: checkout
      path: /
      hosts: ["shop.example.com"]
      backends:
        - endpoint: http://checkout-v2:8080
          exclusive: true              # testers always get v2
          match:
            - source: header
              name: X-Beta-Tester
              operator: equals
              value: "true"
        - endpoint: http://checkout-v1:8080
          weight: 90
        - endpoint: http://checkout-v2:8080
          weight: 10
      healthCheck:
        path: /healthz
        interval: 15s
        timeout: 5s
```

**See also:** [Canary Deployments](./usermanual/canary-deployment.md), [Load Balancing](./monitoring-and-performance/load-balancing.md)

---

## Internal services with a private CA

**The problem:** internal services should use HTTPS, but their hostnames aren't public, so a public CA like Let's Encrypt can't issue certificates for them.

**With Goma:** point CertManager at your own CA — [Certio](https://github.com/jkaninda/certio) over ACME, or HashiCorp Vault PKI — and internal routes get certificates issued and renewed automatically, while public routes keep using Let's Encrypt.

```yaml
certManager:
  defaultProvider: letsencrypt
  providers:
    letsencrypt:
      type: acme
      acme:
        email: ops@example.com
    certio:
      type: acme
      acme:
        email: ops@example.com
        directoryUrl: https://certio.corp.example.com/acme/directory
        eab:
          kid: "<kid>"
          hmacKey: ${GOMA_CERTIO_EAB_HMAC}
```

Routes choose their CA with `tls.provider: certio`.

**See also:** [Private CA with Certio](./usermanual/tls.md#private-ca-with-certio), [HashiCorp Vault (PKI)](./usermanual/tls.md#hashicorp-vault-pki)

---

## One entry point for every protocol

**The problem:** besides REST APIs, you run WebSocket services, gRPC APIs, and TCP or UDP services such as databases, and don't want a separate proxy for each.

**With Goma:** WebSocket and gRPC are routed like any HTTP route, and TCP and UDP traffic is forwarded through dedicated pass-through entry points, all in the same configuration.

**See also:** [TCP, UDP & gRPC](./usermanual/tcp-udp-grpc.md)

---

## Where to go next

- New to Goma Gateway? Start with the [Quickstart](./quickstart/index.md).
- Want the full list of capabilities? See [Features](./index.md#features).
- Running in production? Read [Running Behind a Proxy](./usermanual/running-behind-a-proxy.md) and [Monitoring](./monitoring-and-performance/monitoring.md).
