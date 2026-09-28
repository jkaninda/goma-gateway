---
title: Logging
sidebar_label: Logging
sidebar_position: 2
---


# Logging

The `log` section configures the logging behavior of Goma Gateway, including log levels, output formats, file paths, and optional file rotation.

### Example Configuration

```yaml
version: 2
gateway:
  routes: []
  log:
    level: info             # Log level: trace, debug, info, warn, error, off (default: error)
    filePath: ''            # Log file path (e.g., /etc/goma/goma.log); leave empty for stdout
    format: text            # Log format: text or json
```

---

## Log Levels

The `level` field controls the verbosity of logs.

| Level   | Description                                                                 |
|---------|-----------------------------------------------------------------------------|
| `trace` | Same as `debug`.                                                            |
| `debug` | Detailed debugging information, plus extra fields on request logs (below). |
| `info`  | Standard operational logs, including every proxied request.                 |
| `warn`  | Warnings, and requests that ended with a `4xx` or `5xx` status.             |
| `error` | Errors only, including requests that ended with a `5xx` status (default).   |
| `off`   | Disables all logging.                                                       |

Each proxied request is logged as `Proxied request` at `INFO` for `1xx`–`3xx` responses, `WARN` for `4xx`, and `ERROR` for `5xx`. Because the default level is `error`, set `level: info` to get a full access log.

:::note
At `debug` or `trace`, request logs also include `request_content_length`, `response_body_size`, the query parameters, and the request and response headers. `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, and `X-Auth-Token` values are redacted.
:::

---

## Log Format

Specify the log output format with `format`.

The default is `text`. Set `json` for structured logs.

### Text Format Example

```shell
2025/07/15 17:58:04 INFO Proxied request request_id=82ebf0b80a3c46239f4f9e906ad06377 method=GET url=/path/10 http_version=HTTP/2.0 host=example.com client_ip=192.168.97.1 referer="" status=200 duration=34.10ms route=goma-example user_agent=insomnia/8.2.0
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
  "route": "goma-example",
  "user_agent": "insomnia/8.2.0"
}
```

To add custom fields (headers, query parameters, cookies) to request logs, use the [`accessLog`](../middlewares/access-log.md) middleware.

---

## Setting the Log Level

### Using Environment Variables

```shell
GOMA_LOG_LEVEL=debug
```

`GOMA_LOG_LEVEL` takes precedence over `log.level`. `GOMA_LOG_FORMAT` and `GOMA_LOG_FILE` are used only when `log.format` and `log.filePath` are not set in the configuration file.

### Using Configuration File

```yaml
gateway:
  log:
    level: debug         # Verbose logging
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

When `filePath` is set, you can enable automatic log file rotation using the following optional fields:

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
