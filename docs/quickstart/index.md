---
title: Quickstart
layout: home
nav_order: 2
---

# Quickstart

## Prerequisites

Ensure the following utilities are installed:
- **Docker**
- **Kubernetes** (for Kubernetes installation)

## Installation

### Step 1: Generate the Configuration File

Run the following command to generate a default configuration file:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/config.yml
```

### Step 2: Update the Configuration File

Edit the generated `config.yml` file to define your routes and customize settings as needed.

### Step 3: Validate the Configuration File

Check your configuration for errors with:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config check --config /etc/goma/config.yml
```
### Step 4: Start the Server
Launch the Goma Gateway server with the validated configuration:

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 -p 8080:8080 \
 jkaninda/goma-gateway server --config /etc/goma/config.yml
```
### Next Steps

Congratulations! Your Goma Gateway is now up and running, ready to route traffic to your backend services.

Explore the [documentation](https://jkaninda.github.io/goma-gateway/) for advanced features, including Kubernetes integration and custom resource definitions.