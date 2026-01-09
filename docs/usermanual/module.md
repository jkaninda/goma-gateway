---
title: Custom Module Development (Plugin Development)
layout: default
parent: User Manual
nav_order: 13
---


# Custom Module Development (Plugin Development)

Goma Gateway allows you to create **custom modules** (plugins) to extend its functionality. This guide will walk you through creating, building, and integrating a custom module into Goma Gateway.

---

## 1. Creating a Custom Module

Initialize a new Go module for your plugin:

```bash
go mod init github.com/yourusername/yourmodule
```

### 1.1 Importing Goma Gateway Dependencies

Ensure your module imports the necessary Goma Gateway packages:

```bash
go get github.com/jkaninda/goma-gateway
```

Create a new Go file for your plugin, e.g., `myplugin.go`.

```go
package main

import (
	"fmt"
	"github.com/jkaninda/goma-gateway/pkg/plugins"
	"log/slog"
	"net/http"
)

// MyPlugin is a custom middleware plugin
type MyPlugin struct {
	paths []string
	cfg   map[string]interface{}
}

// Name returns the plugin name
func (m *MyPlugin) Name() string { return "myPlugin" }

// Configure initializes the plugin with its configuration
func (m *MyPlugin) Configure(rule interface{}) error {
	if cfg, ok := rule.(map[string]interface{}); ok {
		m.cfg = cfg
		return nil
	}
	return fmt.Errorf("invalid config format")
}

// Validate ensures the plugin configuration is correct
func (m *MyPlugin) Validate() error {
	return nil
}

// Handler returns the middleware handler function
func (m *MyPlugin) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range m.paths {
			if r.URL.Path == p {
				fmt.Printf("Custom middleware triggered for path %s\n", r.URL.Path)
			}
		}

		if msg, ok := m.cfg["message"]; ok {
			fmt.Printf("Custom message from config: %s\n", msg)
		}

		slog.Info("Custom middleware triggered",
			"path", r.URL.Path,
			"plugin", m.Name(),
			"paths", m.paths,
		)

		next.ServeHTTP(w, r)
	})
}

// WithPaths sets the paths for which this middleware should be applied
func (m *MyPlugin) WithPaths(paths []string) {
	m.paths = paths
}

// New is the exported constructor function for Goma Gateway
func New() plugins.Middleware {
	return &MyPlugin{}
}
```

---

## 2. Building the Module

Build your Go plugin as a shared object file:

```bash
go build -buildmode=plugin -o myplugin.so myplugin.go
```

This produces a `.so` file that Goma Gateway can load.

---

## 3. Integrating the Custom Module into Goma Gateway

### 3.1 Plugin Configuration

Specify the path to your compiled plugin files in the Goma Gateway configuration:

```yaml
version: 2
gateway:
  log:
    level: debug
  entryPoints:
    web:
      address: "[::]:80"   # Bind HTTP server to port 80 (IPv6 compatible)
    webSecure:
      address: "[::]:443"  # Bind HTTPS server to port 443 (IPv6 compatible)
middlewares: []

certManager:
  provider: acme
  acme:
    email: admin@example.com

plugins:
  path: /etc/goma/extra/plugins  # Directory containing your .so plugin files
```

### 3.2 Middleware Configuration

Add your custom plugin to the `middlewares` section of your configuration:

```yaml
middlewares:
  - name: my-plugin        # Unique name for the middleware
    type: myPlugin         # Must match the Name() method in your plugin
    rule:
      message: "Hello from plugin"
      enabled: true
```

### 3.3 Applying Middleware to a Route

Attach your custom middleware to a specific route:

```yaml
routes:
  - name: api-example
    hosts:
      - api.example.com
    path: /
    target: http://api-example:8080
    middlewares: ["my-plugin"]
```

---

### Notes

* Make sure the `type` in the middleware configuration matches the `Name()` method of your plugin.
* The `WithPaths` method allows you to restrict the middleware to specific routes.
* Always build the plugin with `-buildmode=plugin` for compatibility with Goma Gateway.


