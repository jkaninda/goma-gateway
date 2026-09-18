---
title: Docker
sidebar_label: Docker
sidebar_position: 4
---

# Docker Installation

Run Goma Gateway easily with Docker. 

For more details, visit the [Docker Hub repository](https://hub.docker.com/r/jkaninda/goma-gateway).

Check out [Docker Compose templates](https://github.com/jkaninda/goma-gateway/tree/main/examples) for built-in orchestration and scalability.

---

## 1. Initialize Configuration

Generate a configuration file using the following command:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/config.yml
```
If no file is provided, a default configuration is created at /etc/goma/goma.yml.

## 2. Validate Configuration

Check your configuration file for errors:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway config check --config /etc/goma/config.yml

```

## 3. Start the Server with Custom Config

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway server --config /etc/goma/config.yml
```
## 4. Health Checks

Goma Gateway provides the following health check endpoints:
- Gateway Health:
  - `/readyz`
  - `/healthz`
- Routes Health: `/healthz/routes`

## 5. Simple Deployment with Docker Compose

Here’s an example of deploying Goma Gateway using Docker Compose:

```shell
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

## 6. Running as a Non-Root User

The container **runs as root by default**. That is what lets the gateway bind
ports **80** and **443** directly, so a configuration using the standard ports
works with no extra setup.

If you would rather run unprivileged, the image ships a `goma` user with
**uid/gid 10001**, which owns `/etc/goma`, `/etc/goma/extra` and
`/etc/letsencrypt`:

```shell
docker run --rm --name goma-gateway \
 --user 10001:10001 \
 -v "${PWD}/config:/etc/goma/" \
 -p 80:8080 -p 443:8443 \
 jkaninda/goma-gateway server --config /etc/goma/config.yml
```

Or in Compose:

```yaml
services:
  goma-gateway:
    image: jkaninda/goma-gateway
    user: "10001:10001"
    ports:
      - "80:8080"
      - "443:8443"
    volumes:
      - ./config:/etc/goma/
```

Three things to keep in mind:

* **Ports below 1024 need privileges.** Keep the gateway on its `8080`/`8443`
  defaults and publish the standard ports from the host, as above. If you would
  rather the gateway itself listen on 80/443 while staying unprivileged, grant
  only that one capability:

  ```shell
  docker run --cap-drop ALL --cap-add NET_BIND_SERVICE --user 10001:10001 ...
  ```

* **Mounted volumes must be readable by uid 10001.** A gateway that previously
  ran as root leaves root-owned files behind, so `chown -R 10001:10001` the
  config and Let's Encrypt volumes before switching.

* **ACME needs to write.** `/etc/letsencrypt` is mode `0700` and owned by 10001,
  so a named volume mounted there works; a bind mount from the host does not
  unless you chown it first.

In Kubernetes the equivalent is a pod or container `securityContext` — see the
[Kubernetes installation guide](kubernetes.md).
