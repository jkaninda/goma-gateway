---
title: Why Use Goma Gateway?
sidebar_label: Why Use Goma Gateway?
sidebar_position: 2
---

# Why Use Goma Gateway?

Goma Gateway is a **security-focused, cloud-native API Gateway**. This page explains what that means in practice. For the complete list of capabilities, see [Features](./index.md#features).

## Security at the edge, not bolted on

Every request to your services passes through the gateway, which makes it the natural place to enforce security once instead of re-implementing it in every service.

* **Encryption without the busywork**: automatic HTTPS with Let's Encrypt, custom certificates, and [mutual TLS](./usermanual/mtls.md) for client authentication.
* **Identity at the edge**: Basic Auth, JWT, OAuth, OpenID Connect, LDAP, and ForwardAuth are built in, so backends receive only authenticated traffic.
* **Defense in depth**: access policies, geo-blocking, bot detection, exploit protection, body size limits, and [rate limiting](./middlewares/rate-limit.md) with automatic banning are all middleware you attach per route.

Security features are configured in the same declarative YAML as your routes, so they are reviewed, versioned, and deployed like the rest of your configuration.

## Cloud-native by design

Goma Gateway is built to run where your services run: containers, Kubernetes, and dynamic, horizontally scaled environments.

* **Kubernetes-native**: the [Kubernetes Operator](./operator-manual/index.md) manages gateways, routes, and middleware as custom resources.
* **Dynamic configuration**: [providers](./usermanual/providers.md) feed configuration from files, HTTP, Docker labels, or Kubernetes, and changes apply with zero downtime.
* **Scales horizontally**: gateway instances are stateless, with Redis available to [share rate-limit and cache state](./monitoring-and-performance/distributed-instances.md) across replicas.
* **Orchestrator-friendly**: [health and readiness endpoints](./usermanual/healthcheck.md), environment-variable configuration, and Prometheus metrics fit standard deployment and monitoring tooling.

## A focused data plane

Goma Gateway deliberately does one job: handling traffic. Management UIs, service discovery, and orchestration live in [separate projects](./index.md#ecosystem) such as Goma Admin and the Kubernetes Operator.

This keeps the gateway small, fast, and easier to audit, which matters for the component that sits in front of everything else. You add a control plane only if you need one.

## When Goma Gateway is a good fit

* Public APIs that need authentication, rate limiting, and TLS without extra infrastructure
* Internal microservices on Kubernetes or Docker that need consistent routing and access control
* Legacy applications that need modern security (HTTPS, SSO, access policies) placed in front of them without code changes
* Teams that manage infrastructure through GitOps and want gateway configuration in version control
