---
title: Logging
layout: default
parent: Quickstart
nav_order: 6
---


# Logging

### Set the log level to TRACE

Setting the log level to trace configures the server to trace-log all the headers given in forward auth requests.

This is helpful to confirm that certain required Headers are correctly forwarded from the reverse proxy.



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