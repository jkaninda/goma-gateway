---
title: Overview
layout: home
nav_order: 1
---

# About Goma Gateway
{:.no_toc}
Goma Gateway is a lightweight API Gateway.

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/logo.png" width="150" alt="Goma logo">

It comes with a lot of integrated features, such as:

- Reverse proxy
- RESTFull API Gateway management
- Domain/host based request routing
- Multi domain request routing
- Cross-Origin Resource Sharing (CORS)
- Backend errors interceptor
- Authentication middleware
    - JWT `client authorization based on the result of a request`
    - Basic-Auth
- Rate limiting
    - In-Memory Token Bucket based
    - In-Memory client IP based

Declare your routes and middlewares as code.

Architecture:
<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/goma-gateway.png" width="912" alt="Goma archi">

We are open to receiving stars, PRs, and issues!


{: .fs-6 .fw-300 }

---

The [jkaninda/goma-gateway](https://hub.docker.com/r/jkaninda/goma-gateway) Docker image can be deployed on Docker, Docker Swarm and Kubernetes. 

It also supports database __encryption__ using GPG.



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

We decided to publish this image as a simpler and more lightweight alternative because of the following requirements:

- The original image is based on `Alpine` and requires additional tools, making it heavy.
- This image is written in Go.
- `arm64` and `arm/v7` architectures are supported.
- Docker in Swarm mode is supported.
- Kubernetes is supported.
