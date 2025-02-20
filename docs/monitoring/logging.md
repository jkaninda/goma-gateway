---
title: Logging
layout: default
parent: Monitoring and Performance
nav_order: 2
---


# Logging

### Set the log level to TRACE

Setting the log level to trace configures the server to trace-log all the headers given in forward auth requests.

This is helpful to confirm that certain required Headers are correctly forwarded from the reverse proxy.

### Log Level:
- info
- warn
- error
- debug
- trace
- off

### Access Log Format

```shell
method=GET url=/path/10 client_ip=192.168.16.15 status=200 duration=436.4ms route=Example content_length=0 user_agent=insomnia/8.2.0
```
### When using the environment variable

Set the Goma log level to TRACE:

Add the following block to your .env file:
```shell
GOMA_LOG_LEVEL=trace
```

### When using a configuration file

Edit the Goma settings and set `logLevel: trace`.

### Disable logging

To disable logs, you need to set `logLevel: off`, it will turn off logs