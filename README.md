# Goma Gateway - simple Lightweight High-Performance Declarative API Gateway Management.

```
   _____                       
  / ____|                      
 | |  __  ___  _ __ ___   __ _ 
 | | |_ |/ _ \| '_ ` _ \ / _` |
 | |__| | (_) | | | | | | (_| |
  \_____|\___/|_| |_| |_|\__,_|
                               
```
Goma Gateway is a lightweight High-Performance Declarative API Gateway Management.

[![Tests](https://github.com/jkaninda/goma-gateway/actions/workflows/test.yml/badge.svg)](https://github.com/jkaninda/goma-gateway/actions/workflows/test.yml)
[![GitHub Release](https://img.shields.io/github/v/release/jkaninda/goma-gateway)](https://github.com/jkaninda/goma-gateway/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/jkaninda/goma-gateway)](https://goreportcard.com/report/github.com/jkaninda/goma-gateway)
[![Go Reference](https://pkg.go.dev/badge/github.com/jkaninda/goma-gateway.svg)](https://pkg.go.dev/github.com/jkaninda/goma-gateway)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jkaninda/goma-gateway?style=flat-square)
![Docker Pulls](https://img.shields.io/docker/pulls/jkaninda/goma-gateway?style=flat-square)


<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/logo.png" width="150" alt="Goma logo">

----

Architecture:

<img src="https://raw.githubusercontent.com/jkaninda/goma-gateway/main/goma-gateway.png" width="912" alt="Goma archi">


## Links:

- [Docker Hub](https://hub.docker.com/r/jkaninda/goma-gateway)
- [Github](https://github.com/jkaninda/goma-gateway)
- [Kubernetes operator](https://github.com/jkaninda/goma-operator)

### [Documentation](https://jkaninda.github.io/goma-gateway)


## Features

It's designed to be straightforward and efficient, offering a rich set of features, including:

### Core Features
- **RESTful API Gateway Management**  
  Simplify the management of your API Gateway with powerful tools.

- **Domain/Host-Based Request Routing**  
  Route requests based on specific domains or hosts.

- **Multi-Domain Request Routing**  
  Handle requests across multiple domains seamlessly.

- **Reverse Proxy**  
  Efficiently forward client requests to backend servers.

- **WebSocket Proxy**  
  Enable real-time communication via WebSocket support.

### Security and Control
- **Cross-Origin Resource Sharing (CORS)**  
  Define and manage cross-origin policies for secure interactions.

- **Custom Headers**  
  Add and modify headers to meet specific requirements.

- **Backend Errors Interceptor**  
  Catch and handle backend errors effectively.

- **Block Common Exploits Middleware**
  - Detect patterns indicating SQL injection attempts.
  - Identify basic cross-site scripting (XSS) attempts.

- **Authentication Middleware**
  - Support for **JWT** with client authorization based on request results.
  - **Basic-Auth** and **OAuth** authentication mechanisms.
- **Access Policy Middleware**

   The Access Policy middleware controls route access by either `allowing` or `denying` requests based on defined rules.

### Monitoring and Performance
- **Logging**  
  Comprehensive request and response logging.

- **Metrics**  
  Gather insights and monitor performance metrics.

- **Rate Limiting**
  - **In-Memory Rate Limiting**: Client IP-based request throttling.
  - **Distributed Rate Limiting**: Leverage Redis for scalable, client IP-based rate limits.

- **Load Balancing**  
  Use a round-robin algorithm for efficient load distribution.

### Configuration and Flexibility
- **Support for Multiple Route and Middleware Configuration Files**  
  Organize routes across multiple `.yml` or `.yaml` files.

- **TLS Support**  
  Ensure secure communication with TLS integration.

- **HTTP Method Restrictions**  
  Limit HTTP methods for specific routes to enhance control.

Declarative API Gateway Management, define your routes and middleware directly in code for seamless configuration.


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
## 2. Check configuration

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway config check --config /etc/goma/config.yml
```

### 3. Run server

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway server
```

### 4. Start server with a custom config
```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 -p 8443:8443 \
 jkaninda/goma-gateway server --config /etc/goma/config.yml
```
### 4. Healthcheck

- Goma Gateway health check: 
  - `/readyz`
  - `/healthz`
- Routes health check: `/healthz/routes`


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

### 6. Kubernetes deployment

-  [Kubernetes installation](https://jkaninda.github.io/goma-gateway/install/kubernetes.html)

- [Kubernetes advanced deployment using CRDs and Operator](https://jkaninda.github.io/goma-gateway/install/kuberntes-advanced.html) 

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