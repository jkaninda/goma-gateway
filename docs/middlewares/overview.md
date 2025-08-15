---
title: Overview
layout: default
parent: Middleware
nav_order: 1
---
# Middlewares

Middleware functions are executed before or after a route callback, enabling you to extend the behavior of your routes.

They are an excellent way to implement features like API authentication, access control, or request validation. 

With Goma, you can create custom middleware tailored to your needs and apply them to your routes seamlessly.

## Supported Middleware Types

- **Authentication Middleware**
  - **ForwardAuth**: delegates authorization to a backend service, determining access based on the service's HTTP response.
  - **Basic-Auth**: Verifies credentials through Basic Authentication.
  - **OAuth**: Supports OAuth-based authentication flows.
  - **LDAP**: servers with HTTP Basic Authentication

- **Rate Limiting Middleware**
  - **In-Memory Client IP Based**: Throttles requests based on the client’s IP address using an in-memory store.
  - **Distributed Rate Limiting**: Leverage Redis for scalable, client IP-based rate limits.

- **Access Middleware**
  - Validates user permissions or access rights for specific route paths.
- **Access Policy Middleware**
  - Controls route access by either `allowing` or `denying` requests based on defined rules.

Middleware provides a flexible and powerful way to enhance the functionality, security, and performance of your API.

## Configuration Options

- **`name`** (`string`): Name of the middleware without white space.
- **`type`** (`string`): Type of the middleware.
- **`paths`** (`array of string`): Paths to prevent or protect.
- **`rule`** (`dictionary`): Middleware rule, changes depending on their type.
