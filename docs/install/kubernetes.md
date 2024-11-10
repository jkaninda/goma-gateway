---
title: Kubernetes
layout: default
parent: Installation
nav_order: 4
---

# Kubernetes Installation


Details about how to use Goma in Kubernetes can be found on the hub.docker.com repo hosting the image: Goma.
We also have some cool examples with [Kubernetes deployment template](https://github.com/jkaninda/goma-gateway/tree/main/examples) with built-in orchestration and scalability.

## 1. Generate a configuration file

You can generate the configuration file using `config init --output /etc/goma/config.yml` command.

The default configuration is automatically generated if any configuration file is not provided, and is available at `/etc/goma/goma.yml`

```shell
docker run --rm  --name goma-gateway \
 -v "${PWD}/config:/etc/goma/" \
 jkaninda/goma-gateway config init --output /etc/goma/config.yml
```

## 2. Create ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: goma-config
data:
  goma.yml: |
      # Goma Gateway configurations
    version: 0.1.7
    gateway:
      # Proxy write timeout
      writeTimeout: 15
      # Proxy read timeout
      readTimeout: 15
      # Proxy idle timeout
      idleTimeout: 30
      ## SSL Certificate file
      sslCertFile: '' #cert.pem
      ## SSL Private Key file
      sslKeyFile: ''#key.pem
      # Proxy rate limit, it's In-Memory IP based
      rateLimit: 0
      accessLog:    "/dev/Stdout"
      errorLog:     "/dev/stderr"
      ## Enable, disable routes health check
      disableHealthCheckStatus: false
      ## Returns backend route healthcheck errors
      disableRouteHealthCheckError: false
      # Disable display routes on start
      disableDisplayRouteOnStart: false
      # disableKeepAlive allows enabling and disabling KeepALive server
      disableKeepAlive: false
      # Block common exploits | detect SQL injection, and simple XSS attempts
      blockCommonExploits: false
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
        - name: Public  # Name is optional
          # host Domain/host based request routing
          host: "" # Host is optional
          path: /public
          ## Rewrite a request path
          # e.g rewrite: /store to /
          rewrite: /
          destination:  https://example.com
          # Limit HTTP methods allowed for this route
          methods: [POST, PUT, GET]
          #DisableHeaderXForward Disable X-forwarded header.
          # [X-Forwarded-Host, X-Forwarded-For, Host, Scheme ]
          # It will not match the backend route, by default, it's disabled
          disableHeaderXForward: false
          # Internal health check
          healthCheck: '' #/internal/health/ready
          # Route Cors, global cors will be overridden by route
          cors:
            # Route Origins Cors, route will override global cors origins
            origins:
              - https://dev.example.com
              - http://localhost:3000
              - https://example.com
            # Route Cors headers, route will override global cors headers
            headers:
              Access-Control-Allow-Methods: 'GET'
              Access-Control-Allow-Headers: 'Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id'
              Access-Control-Allow-Credentials: 'true'
              Access-Control-Max-Age: 1728000
          ##### Apply middlewares to the route
          ## The name must be unique
          ## List of middleware name
          middlewares:
            - api-forbidden-paths
        # Example of a route | 2
        - name: Basic auth
          path: /protected
          rewrite: /
          destination:  https://example.com
          methods: []
          healthCheck:
          cors: {}
          middlewares:
            - api-forbidden-paths
            - basic-auth
    
    #Defines proxy middlewares
    # middleware name must be unique
    middlewares:
      # Enable Basic auth authorization based
      - name: basic-auth
        # Authentication types | jwt, basic, OAuth
        type: basic
        paths:
          - /user
          - /admin
          - /account
        rule:
          username: admin
          password: admin
      #Enables JWT authorization based on the result of a request and continues the request.
      - name: google-auth
        # Authentication types | jwt, basic, OAuth
        # jwt authorization based on the result of backend's response and continue the request when the client is authorized
        type: jwt
        # Paths to protect
        paths:
          - /protected-access
          - /example-of-jwt
          #- /* or wildcard path
        rule:
          # This is an example URL
          url: https://www.googleapis.com/auth/userinfo.email
          # Required headers, if not present in the request, the proxy will return 403
          requiredHeaders:
            - Authorization
        #  You can also get headers from the authentication request result and inject them into the next request header or params.
        #  In case you want to get headers from the authentication service and inject them into the next request headers.
        #  Set the request variable to the given value after the authorization request completes.
        # In case you want to get headers from the authentication service and inject them into the next request headers.
        #  Key is authentication request response header Key. Value is the next Request header Key.
        headers:
          userId: Auth-UserId
          userCountryId: Auth-UserCountryId
        # In case you want to get headers from the Authentication service and inject them to the next request params.
        #Key is authentication request response header Key. Value is the next Request parameter Key.
        params:
          userCountryId: countryId
      # The server will return 403
      - name: api-forbidden-paths
        type: access
        ## prevents access paths
        paths:
          - /swagger-ui/*
          - /v2/swagger-ui/*
          - /api-docs/*
          - /internal/*
          - /actuator/*
```
## 3. Create Kubernetes deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goma-gateway
spec:
  selector:
    matchLabels:
      app: goma-gateway
  template:
    metadata:
      labels:
        app: goma-gateway
    spec:
      containers:
        - name: goma-gateway
          image: jkaninda/goma-gateway
          command: ["goma","server"]
          resources:
            limits:
              memory: "128Mi"
              cpu: "200m"
          ports:
            - containerPort: 8080
          livenessProbe:
            httpGet:
              path: /health/live
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 30
            timeoutSeconds: 10
          readinessProbe:
            httpGet:
              path: /health/live
              port: 8080
            initialDelaySeconds: 15
            periodSeconds: 30
            timeoutSeconds: 10
          volumeMounts:
            - name: config
              mountPath: /etc/goma/
      volumes:
        - name: config
          configMap:
            name: goma-config
```