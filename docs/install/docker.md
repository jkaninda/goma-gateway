---
title: Docker
layout: default
parent: Installation
nav_order: 4
---

# Docker Installation

Details about how to use Goma in Docker can be found on the hub.docker.com repo hosting the image: Goma.
We also have some cool examples with [Docker Compose template](https://github.com/jkaninda/goma-gateway/tree/main/examples) with built-in orchestration and scalability.

## 1. Initialize configuration

You can generate the configuration file using `config init --output /etc/goma/config.yml` command.

The default configuration is automatically generated if any configuration file is not provided, and is available at `/etc/goma/goma.yml`

```shell
docker run --rm  --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/config.yml
```
## 2. Check configuration

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway config check --config /etc/goma/config.yml
```

### 3. Start server with a custom config
```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway server --config /config/config.yml
```
### 4. Healthcheck

- Goma Gateway health check: `/health/live`
- Routes health check: `health/routes`

### 5. Simple deployment in docker compose file

```yaml
services:
  goma-gateway:
    image: jkaninda/goma-gateway
    command: server
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./config:/etc/goma/
```