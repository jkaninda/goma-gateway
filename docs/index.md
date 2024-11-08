---
title: Overview
layout: home
nav_order: 1
---

# Goma Gateway
{:.no_toc}
Goma Gateway is a lightweight API Gateway Management.

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/logo.png" width="150" alt="Goma logo">

It's designed to be straightforward and efficient, offering features, like:

- RESTFull API Gateway management
- Domain/host based request routing
- Multi domain request routing
- Reverse Proxy
- Websocket Proxy
- Cross-Origin Resource Sharing (CORS)
- Custom Headers
- Backend Errors interceptor
- Support TLS
- Block common exploits middleware
  - Patterns to detect SQL injection attempts
  - Pattern to detect simple XSS attempts
- Authentication middleware
  - JWT `client authorization based on the result of a request`
  - Basic-Auth
  - OAuth
- Rate limiting
  - In-Memory Token Bucket based
  - In-Memory client IP based
- Limit HTTP methods allowed for a particular route.


Declare your routes and middlewares as code.

----
Architecture:
<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/goma-gateway.png" width="912" alt="Goma archi">

We are open to receiving stars, PRs, and issues!


{: .fs-6 .fw-300 }

---

The [jkaninda/goma-gateway](https://hub.docker.com/r/jkaninda/goma-gateway) Docker image can be deployed on Docker, Docker in Swarm mode, and Kubernetes. 


## Available image registries

This Docker image is published to both Docker Hub and the GitHub container registry.
Depending on your preferences and needs, you can reference both `jkaninda/goma-gateway` as well as `ghcr.io/jkaninda/goma-gateway`:

```
docker pull jkaninda/goma-gateway
docker pull ghcr.io/jkaninda/goma-gateway
```

Documentation references Docker Hub, but all examples will work using ghcr.io just as well.

## Supported Engines

This image is developed and tested against the Docker CE engine exclusively.
While it may work against different implementations, there are no guarantees about support for non-Docker engines.

## References

We decided to publish this image as a simpler and more lightweight because of the following requirements:

- The original image is based on `Alpine` and requires additional tools, making it heavy.
- This image is written in Go.
- `arm64` and `arm/v7` architectures are supported.
- Docker in Swarm mode is supported.
- Kubernetes is supported.
