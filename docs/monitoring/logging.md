---
title: Logging
layout: default
parent: Monitoring and Performance
nav_order: 2
---


# Logging

The `log` section configures the logging behavior of Goma Gateway, including log levels, output formats, file paths, and optional file rotation.

### Example Configuration

```yaml
version: 2
gateway:
  routes: []
  log:
    level: info             # Log level: debug, trace, info, warn, error, off (default: error)
    filePath: ''            # Log file path (e.g., /etc/goma/goma.log); leave empty for stdout
    format: text            # Log format: text or json
```

---

## Log Levels

The `level` field controls the verbosity of logs.

| Level   | Description                                                           |
|---------|-----------------------------------------------------------------------|
| `trace` | Logs all debug information, including header tracing for forwardAuth. |
| `debug` | Detailed debugging information.                                       |
| `info`  | Standard operational logs (default).                                  |
| `warn`  | Indicates potentially harmful situations.                             |
| `error` | Logs only errors.                                                     |
| `off`   | Disables all logging.                                                 |

> 💡 **Note**: Use `trace` level to inspect all headers forwarded in `forwardAuth` requests—this is useful for debugging header propagation from reverse proxies.

---

## Log Format

Specify the log output format with `format`.

### Text Format Example

```shell
2025/07/15 17:58:04 INFO Proxied request request_id=82ebf0b80a3c46239f4f9e906ad06377 method=GET url=/path/10 http_version=HTTP/2.0 host=example.com client_ip=192.168.97.1 referer="" status=200 duration=34.10ms request_content_length=0 route=goma-example user_agent=insomnia/8.2.0
```

### JSON Format Example

```json
{
  "time": "2025-07-15T17:59:41.220Z",
  "level": "INFO",
  "msg": "Proxied request",
  "request_id": "7364d923ec9747598073fa577ed37321",
  "method": "GET",
  "url": "/path/10",
  "http_version": "HTTP/2.0",
  "host": "example.com",
  "client_ip": "192.168.97.1",
  "referer": "",
  "status": 200,
  "duration": "6.99ms",
  "request_content_length": "0",
  "route": "goma-example",
  "user_agent": "insomnia/8.2.0"
}
```

---

## Setting the Log Level

### Using Environment Variables

Add the following to your `.env` file:

```shell
GOMA_LOG_LEVEL=trace
```

### Using Configuration File

```yaml
gateway:
  log:
    level: trace         # Enable full tracing
    format: json         # Use structured logs
```

---

## Disabling Logging

To disable all logging, set the level to `off`:

```yaml
gateway:
  log:
    level: off
    filePath: /etc/goma/goma.log
    format: text
```

---

## File Rotation Support

You can enable automatic log file rotation using the following optional fields:

```yaml
gateway:
  log:
    level: info
    filePath: /etc/goma/goma.log
    format: text
    maxAgeDays: 6       # Maximum number of days to retain old log files
    maxBackups: 3       # Maximum number of backup files to retain
    maxSizeMB: 100      # Maximum size in megabytes before log rotation
```
