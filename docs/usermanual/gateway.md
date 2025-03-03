---
title: Gateway
layout: default
parent: User Manual
nav_order: 1
---

# Gateway

The Gateway serves as the entry point to the server. This section provides options to configure the proxy server, define routes, and specify additional routes. 

These settings enable precise control over traffic flow and routing within your deployment.

## Configuration Options

- **`redis`**: Redis configuration settings.
- **`tls`**: Global TLS configuration .
- **`writeTimeout`** (`integer`): Timeout for writing responses (in seconds).
- **`readTimeout`** (`integer`): Timeout for reading requests (in seconds).
- **`idleTimeout`** (`integer`): Timeout for idle connections (in seconds).
- **`blockCommonExploits`** (`boolean`): Enable or disable blocking of common exploits.
- **`disableHealthCheckStatus`** (`boolean`): Enable or disable exposing the health check route status.
- **`disableRouteHealthCheckError`** (`boolean`): Enable or disable returning health check error responses for routes.
- **`disableKeepAlive`** (`boolean`): Enable or disable `keepAlive` for the proxy.
- **`entroiponts`**: Define the network addresses where web servers will listen for incoming HTTP and HTTPS requests.
- **`enableMetrics`** (`boolean`): Enable or disable server metrics collection.
- **`enableStrictSlash`** (`boolean`): Enable or disable, the router will match the path with or without a trailing slash.


## TLS Configuration

Goma Gateway allows you to define global TLS certificates for securing routes.

These certificates are used to encrypt traffic between clients and the gateway.

#### Keys Configuration

You can define a list of TLS certificates for the routes using the following keys:

- **`cert`** (`string`):  
  Specifies the TLS certificate. This can be provided as:
  - A file path to the certificate.
  - Raw certificate content.
  - A base64-encoded certificate.

- **`key`** (`string`):  
  Specifies the private key corresponding to the TLS certificate. 
   
  This can be provided as:
  - A file path to the private key.
  - Raw private key content.
  - A base64-encoded private key.

---
### CORS Configuration

Customize Cross-Origin Resource Sharing (CORS) settings for the proxy:

- **`origins`** (`array of strings`): List of allowed origins.
- **`headers`** (`map[string]string`): Custom headers to include in responses.

### Error Interceptor
- **`enabled`** (`boolean`): Determines whether the backend error interceptor is active.  
  *Default: `false`*
- **`contentType`** (`string`): Specifies the `Content-Type` header of the response, such as `application/json` or `text/plain`.
- **`errors`** (`array`): A collection of error configurations defining which HTTP status codes to intercept and their corresponding custom responses.

### EntryPoints Configuration

The `entryPoints` section in Goma Gateway's configuration allows you to define the network addresses where your web servers will listen for incoming HTTP and HTTPS requests. This section is crucial for setting up custom ports or IP addresses for your web services.

#### Default Behavior
By default, Goma Gateway listens on:
- **Web (HTTP)**: Port `8080`
- **WebSecure (HTTPS)**: Port `8443`

However, you can customize these settings to use different ports or bind to specific IP addresses as needed.

#### Configuration Structure

##### `web` Entry Point
- **Purpose**: Configures the address for the HTTP server.
- **Key**: `address` (`string`)
  - **Description**: Specifies the network address and port where the HTTP server will listen. The format is typically `:port` (e.g., `":80"`) or `ip:port` (e.g., `"192.168.1.1:80"`).

##### `webSecure` Entry Point
- **Purpose**: Configures the address for the HTTPS server.
- **Key**: `address` (`string`)
  - **Description**: Specifies the network address and port where the HTTPS server will listen. Similar to the `web` entry point, the format is `:port` or `ip:port`.

  
### Extra Config

Define custom routes and middlewares for greater flexibility:

- **`directory`** (`string`): The directory path where additional route and middleware configuration files are stored.
- **`watch`** (`boolean`): Watch the directory for changes and update routes dynamically.

### Routes

Define the main routes for the Gateway, enabling routing logic for incoming requests.

---

### Minimal Configuration

```yaml
version: 2  # Configuration version
gateway:
  routes: []
```
### Example: Customizing EntryPoints

To override the default ports and bind the web servers to standard HTTP (`:80`) and HTTPS (`:443`) ports, you can modify the configuration as shown below:

```yaml
version: 2  # Configuration version
gateway:
  entryPoints:
    web:
      address: ":80"  # Bind HTTP server to port 80
    webSecure:
      address: ":443" # Bind HTTPS server to port 443
```

## Example Configuration

```yaml
version: 2  # Configuration version
gateway:
  # Timeout settings for the gateway
  writeTimeout: 15  # Maximum time (in seconds) to wait for a write operation to complete
  readTimeout: 15   # Maximum time (in seconds) to wait for a read operation to complete
  idleTimeout: 30   # Maximum idle time (in seconds) before closing an inactive connection

  # TLS configuration for securing the gateway
  tls:
    keys:  # List of TLS certificates and private keys
      - cert: /etc/goma/cert.pem  # File path to the TLS certificate
        key: /etc/goma/key.pem    # File path to the private key
      - cert: |  # Raw certificate content (PEM format)
          -----BEGIN CERTIFICATE-----
        key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS...  # Base64-encoded private key

  # Logging Configuration
  log:
    level: info # Logging level (options: debug, trace, off). default: error
    filePath: stdout # Path for log files (eg. /etc/goma/goma.log). default: stdout

  # Gateway behavior settings
  disableRouteHealthCheckError: false  # Enable/disable health check error logging
  disableDisplayRouteOnStart: false    # Enable/disable displaying routes on startup
  disableKeepAlive: false              # Enable/disable keep-alive connections
  disableHealthCheckStatus: false      # Enable/disable health check status updates
  blockCommonExploits: false           # Enable/disable blocking common web exploits

  # Error interceptor configuration
  errorInterceptor:
    enabled: true  # Enable/disable error interception
    contentType: "application/json"  # Content type for error responses
    errors:  # Custom error responses for specific HTTP status codes
      - status: 401  # Unauthorized
        body: ""     # Empty response body
      - status: 500  # Internal Server Error
        body: "Internal server error"  # Custom error message

  # CORS (Cross-Origin Resource Sharing) configuration
  cors:
    origins:  # Allowed origins for CORS
      - http://localhost:8080
      - https://example.com
    headers:  # Custom headers for CORS
      X-Custom-Header: "Value"  # Example custom header
      Access-Control-Allow-Credentials: "true"  # Allow credentials (e.g., cookies)
      Access-Control-Allow-Headers: Origin, Authorization, Accept, Content-Type, Access-Control-Allow-Headers, X-Client-Id, X-Session-Id  # Allowed headers
      Access-Control-Max-Age: "1728000"  # Max age for preflight requests (in seconds)

  # Extra configuration for additional files (e.g., routes and middleware)
  extraConfig:
    directory: /etc/goma/extra  # Directory path for additional configuration files
    watch: true  # Enable/disable watching the directory for changes

  # Routes configuration (empty in this example)
  routes: []  # Define routes for the gateway (e.g., path, backends, health checks)
```