---
title: Intro
layout: default
parent: Middleware
nav_order: 1
---
# Middlewares

Middleware is a function executed before (or after) the route callback.

This is a great way to add API authentication checks, or to validate that the user has permission to access the route.

With Goma you can create your middleware based on the type you want and apply it on your routes

Goma Gateway supports :

- Authentication middleware
    - JWT `client authorization based on the result of a request`
    - Basic-Auth
    - OAuth
- Rate limiting middleware
    - In-Memory client IP based
- Access middleware 