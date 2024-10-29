# Goma Gateway - simple lightweight API Gateway and Reverse Proxy.

```
   _____                       
  / ____|                      
 | |  __  ___  _ __ ___   __ _ 
 | | |_ |/ _ \| '_ ` _ \ / _` |
 | |__| | (_) | | | | | | (_| |
  \_____|\___/|_| |_| |_|\__,_|
                               
```
Goma Gateway is a lightweight API Gateway and Reverse Proxy.

Simple, easy to use, and configure.

[![Build](https://github.com/jkaninda/goma-gateway/actions/workflows/release.yml/badge.svg)](https://github.com/jkaninda/goma-gateway/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/jkaninda/goma-gateway)](https://goreportcard.com/report/github.com/jkaninda/goma-gateway)
[![Go Reference](https://pkg.go.dev/badge/github.com/jkaninda/goma-gateway.svg)](https://pkg.go.dev/github.com/jkaninda/goma-gateway)
![Docker Image Size (latest by date)](https://img.shields.io/docker/image-size/jkaninda/goma-gateway?style=flat-square)

## Links:

- [Docker Hub](https://hub.docker.com/r/jkaninda/goma-gateway)
- [Github](https://github.com/jkaninda/goma-gateway)

### Feature

- [x] Reverse proxy
- [x] API Gateway
- [x] Domain/host based request routing
- [x] Multi domain request routing
- [x] Cors
- [ ] Support TLS
- [x] Backend errors interceptor
- [x] Authentication middleware
  - [x] JWT `HTTP Bearer Token`
  - [x] Basic-Auth
  - [ ] OAuth
- [x] Implement rate limiting
  - [x] In-Memory Token Bucket based
  - [x] In-Memory client IP based
  - [ ] Distributed Rate Limiting for Token based across multiple instances using Redis
  - [ ] Distributed Rate Limiting for In-Memory client IP based across multiple instances using Redis

## Usage

### 1. Initialize configuration

```shell
docker run --rm  --name goma-gateway \
 -v "${PWD}/config:/config" \
 jkaninda/goma-gateway config init --output /config/goma.yml
```
### 2. Run server

```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/config" \
 -p 80:80 \
 jkaninda/goma-gateway server
```

### 3. Start server with a custom config
```shell
docker run --rm --name goma-gateway \
 -v "${PWD}/config:/config" \
 -p 80:80 \
 jkaninda/goma-gateway server --config /config/config.yml
```
### 4. Healthcheck

- Goma Gateway readiness: `/readyz`
- Routes health check: `/healthz`

[http://localhost/healthz](http://localhost/healthz)

[http://localhost/readyz](http://localhost/readyz)

> Healthcheck response body

```json
{
	"status": "healthy",
	"routes": [
		{
			"name": "Store",
			"status": "healthy",
			"error": ""
		},
		{
			"name": "Authentication service",
			"status": "unhealthy",
          "error": "error performing HealthCheck request: Get \"http://authentication-service:8080/internal/health/ready\": dial tcp: lookup authentication-service on 127.0.0.11:53: no such host "
          
		},
		{
			"name": "Notification",
			"status": "undefined",
			"error": ""
		}
	]
}
```


Create a config file in this format
## Customize configuration file

Example of configuration file
```yaml
## Goma - simple lightweight API Gateway and Reverse Proxy.
# Goma Gateway configurations
gateway:
  ########## Global settings
  listenAddr: 0.0.0.0:80
  # Proxy write timeout
  writeTimeout: 15
  # Proxy read timeout
  readTimeout: 15
  # Proxy idle timeout
  idleTimeout: 60
  # Proxy rate limit, it's In-Memory Token Bucket
  # Distributed Rate Limiting for Token based across multiple instances is not yet integrated
  rateLimiter: 0
  accessLog:    "/dev/Stdout"
  errorLog:     "/dev/stderr"
  ## Returns backend route healthcheck errors
  disableRouteHealthCheckError: false
  # Disable display routes on start
  disableDisplayRouteOnStart: false
  # interceptErrors intercepts backend errors based on defined the status codes
  interceptErrors:
    - 405
    - 500
  # - 400
  # Proxy Global HTTP Cors
  cors:
    # Global routes cors for all routes
    origins:
      - http://localhost:8080
      - https://example.com
    # Global routes cors headers for all routes
    headers:
      Access-Control-Allow-Headers: 'Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id'
      Access-Control-Allow-Credentials: 'true'
      Access-Control-Max-Age: 1728000
  ##### Define routes
  routes:
    # Example of a route | 1
    - name: Public
      # host Domain/host based request routing
      host: ""
      path: /public
      ## Rewrite a request path
      # e.g rewrite: /store to /
      rewrite: /healthz
      destination:  https://example.com
      #DisableHeaderXForward Disable X-forwarded header.
      # [X-Forwarded-Host, X-Forwarded-For, Host, Scheme ]
      # It will not match the backend route, by default, it's disabled
      disableHeaderXForward: false
      # Internal health check
      healthCheck: '' #/internal/health/ready
      # Route Cors, global cors will be overridden by route
      cors:
        # Route Origins Cors, global cors will be overridden by route
        origins:
          - https://dev.example.com
          - http://localhost:3000
          - https://example.com
        # Route Cors headers, global cors will be overridden by route
        headers:
          Access-Control-Allow-Methods: 'GET'
          Access-Control-Allow-Headers: 'Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id'
          Access-Control-Allow-Credentials: 'true'
          Access-Control-Max-Age: 1728000
      #### Define route blocklist paths
      blocklist:
        - /swagger-ui/*
        - /v2/swagger-ui/*
        - /api-docs/*
        - /internal/*
        - /actuator/*
      ##### Define route middlewares from middlewares names
      ## The name must be unique
      ## List of middleware name
      middlewares:
        # path to protect
        - path: /user
          # Rules defines which specific middleware applies to a route path
          rules:
            - basic-auth #Middleware name
        # path to protect
        - path: /path-example
          # Rules defines which specific middleware applies to a route path
          rules:
            - jwt #Middleware name
        # path to protect
        - path: /admin
          # Rules defines which specific middleware applies to a route path
          rules:
            - basic-auth #Middleware name
        # path to protect
        - path: /path-example
          # Rules defines which specific middleware applies to a route path
          rules:
            - jwt # Middleware name
        - path: /history
          http:
            url: http://security-service:8080/security/authUser
            headers:
              #Key from backend authentication header, and inject to the request with custom key name
              userId: X-Auth-UserId
              userCountryId: X-Auth-UserCountryId
            params:
              userCountryId: X-countryId
    # Example of a route | 2
    - name: Authentication service
      path: /auth
      rewrite: /
      destination: 'http://security-service:8080'
      healthCheck: /internal/health/ready
      cors: {}
      blocklist: []
      middlewares: []
    # Example of a route | 3
    - name: Basic auth
      path: /protected
      rewrite: /
      destination: 'http://notification-service:8080'
      healthCheck:
      cors: {}
      blocklist: []
      middlewares: []

#Defines proxy middlewares
middlewares:
  # Enable Basic auth authorization based
  - name:  basic-auth
    # Authentication types | jwtAuth, basicAuth, auth0
    type: basicAuth
    rule:
      username: admin
      password: admin
  #Enables JWT authorization based on the result of a request and continues the request.
  - name: jwt
    # Authentication types | jwtAuth, basicAuth, OAuth
    # jwt authorization based on the result of backend's response and continue the request when the client is authorized
    type: jwtAuth
    rule:
      # This is an example URL
      url: https://www.googleapis.com/auth/userinfo.email
      # Required headers, if not present in the request, the proxy will return 403
      requiredHeaders:
        - Authorization
      #Sets the request variable to the given value after the authorization request completes.
      #
      # Add header to the next request from AuthRequest header, depending on your requirements
      # Key is AuthRequest's response header Key, and value is Request's header Key
      # In case you want to get headers from the Authentication service and inject them into the next request's headers
      #Sets the request variable to the given value after the authorization request completes.
      #
      # Add header to the next request from AuthRequest header, depending on your requirements
      # Key is AuthRequest's response header Key, and value is Request's header Key
      # In case you want to get headers from the Authentication service and inject them into the next request's headers
      headers:
        userId: X-Auth-UserId
        userCountryId: X-Auth-UserCountryId
      # In case you want to get headers from the Authentication service and inject them to the next request's params
      params:
        userCountryId: countryId
```

## Requirement

- Docker
