---
title: Custom Module Development (Plugin Development)
sidebar_label: Custom Module Development (Plugin Development)
sidebar_position: 13
---


# Custom Module Development (Plugin Development)

Goma Gateway allows you to create **custom modules** (plugins) to extend its functionality. A module is a Go plugin (`.so` file) that provides a middleware. This guide will walk you through creating, building, and integrating a custom module into Goma Gateway.

:::warning[Requirements]
Go plugins are loaded with Go's [`plugin`](https://pkg.go.dev/plugin) package, which works only on Linux, macOS, and FreeBSD, and only in a binary built with `CGO_ENABLED=1`. The Docker image built from the repository's `Dockerfile` uses `CGO_ENABLED=0`, so it cannot load plugins. The plugin and the gateway must also be built with the same Go version and the same versions of every shared dependency, including `goma-gateway` itself.
:::

---

## 1. Creating a Custom Module

Initialize a new Go module for your plugin:

```bash
go mod init github.com/yourusername/yourmodule
```

### 1.1 Importing Goma Gateway Dependencies

Ensure your module imports the necessary Goma Gateway packages, pinned to the version of the gateway you run:

```bash
go get github.com/jkaninda/goma-gateway@<gateway-version>
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

This produces a `.so` file that Goma Gateway can load. The plugin must export a function `New` with the signature `func() plugins.Middleware`; the gateway looks it up by that name.

---

## 3. Integrating the Custom Module into Goma Gateway

### 3.1 Plugin Configuration

Specify the directory containing your compiled plugin files with the top-level `plugins.path` key. The gateway loads every `*.so` file in that directory at startup:

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

plugins:
  path: /etc/goma/extra/plugins  # Directory containing your .so plugin files
```

### 3.2 Middleware Configuration

Add your custom plugin to the `middlewares` section of your configuration:

```yaml
middlewares:
  - name: my-plugin        # Unique name for the middleware
    type: myPlugin         # Must match the Name() method in your plugin
    paths:                 # Optional, passed to WithPaths()
      - /api
    rule:
      message: "Hello from plugin"
```

The `rule` block is passed to `Configure()` as decoded YAML (a `map[string]interface{}` for a mapping), then `Validate()` is called. A middleware whose `Configure()` or `Validate()` returns an error is logged and not registered.

If a `.so` file fails to load, the gateway logs the error and still registers the
plugins that did load. A route using a middleware that was not registered, or
whose `type` matches no loaded plugin, rejects every request with `503`.

### 3.3 Applying Middleware to a Route

Attach your custom middleware to a specific route:

```yaml
gateway:
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

* Make sure the `type` in the middleware configuration matches the `Name()` method of your plugin. If `Name()` returns an empty string, the file name is used.
* `WithPaths` is optional. When the plugin implements it, it receives the middleware's `paths` list, so the plugin can limit itself to those request paths.
* A plugin can also implement `Info() plugins.Info` to report its name, version, and author in the startup logs.
* Always build the plugin with `-buildmode=plugin` for compatibility with Goma Gateway.
* Go cannot unload or reload a plugin that is already loaded, so replacing a `.so` file requires a restart.


