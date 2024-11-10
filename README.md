# Goma Gateway - simple lightweight API Gateway Management.

```
   _____                       
  / ____|                      
 | |  __  ___  _ __ ___   __ _ 
 | | |_ |/ _ \| '_ ` _ \ / _` |
 | |__| | (_) | | | | | | (_| |
  \_____|\___/|_| |_| |_|\__,_|
                               
```
Goma Gateway is a lightweight API Gateway Management.

[![Build](https://github.com/jkaninda/goma-gateway/actions/workflows/release.yml/badge.svg)](https://github.com/jkaninda/goma-gateway/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jkaninda/goma-gateway)](https://goreportcard.com/report/github.com/jkaninda/goma-gateway)
[![Go Reference](https://pkg.go.dev/badge/github.com/jkaninda/goma-gateway.svg)](https://pkg.go.dev/github.com/jkaninda/goma-gateway)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jkaninda/goma-gateway?style=flat-square)

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/logo.png" width="150" alt="Goma logo">

----

Architecture:

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/goma-gateway.png" width="912" alt="Goma archi">


## Links:

- [Docker Hub](https://hub.docker.com/r/jkaninda/goma-gateway)
- [Github](https://github.com/jkaninda/goma-gateway)

### Documentation is found at <https://jkaninda.github.io/goma-gateway>
### Features

It's designed to be straightforward and efficient, offering features, like:

- RESTFull API Gateway management
- Domain/host based request routing
- Multi domain request routing
- Reverse Proxy
- Websocket Proxy
- Cross-Origin Resource Sharing (CORS)
- Custom Headers
- Backend Errors interceptor
- Logging
- Metrics
- Supports Load Balancing, round-robin algorithm
- Support TLS
- Block common exploits middleware
  - Patterns to detect SQL injection attempts
  - Pattern to detect simple XSS attempts
- Authentication middleware
  - JWT `client authorization based on the result of a request`
  - Basic-Auth
  - OAuth 
- Rate limiting, In-Memory client IP based
- Limit HTTP methods allowed for a particular route.

### Todo:
  - [ ] Load Balancing Healthcheck, disable unavailable servers
  - [ ] Blocklist IP address middleware
  - [ ] Distributed Rate Limiting for In-Memory client IP based across multiple instances using Redis

----

## Usage

### 1. Initialize configuration

You can generate the configuration file using `config init --output /etc/goma/config.yml` command.

The default configuration is automatically generated if any configuration file is not provided, and is available at `/etc/goma/goma.yml`

```shell
docker run --rm  --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/goma.yml
```
### 2. Run server

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway server
```

### 3. Start server with a custom config
```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 -p 8443:8443 \
 jkaninda/goma-gateway server --config /etc/goma/config.yml
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
    volumes:
      - ./config:/etc/goma/
```

## Supported Systems

- [x] Linux
- [x] MacOS
- [x] Windows 

Please download the binary from the [release page](https://github.com/jkaninda/goma-gateway/releases).
Init configs:

```shell
./goma config init --output config.yml
```

To run 
```shell
./goma server --config config.yml
```




## Deployment

- Docker
- Kubernetes

## Contributing

The Goma Gateway project welcomes all contributors. We appreciate your help!


## Give a Star! ⭐

If you like or are using Goma Gateway, please give it a star. Thanks!

Please share.


## License

This project is licensed under the Apache 2.0 License. See the LICENSE file for details.


## Copyright

Copyright (c) 2024 Jonas Kaninda