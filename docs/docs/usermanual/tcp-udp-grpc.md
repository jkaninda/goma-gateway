---
title: TCP/UDP/gRPC Forwarding
sidebar_label: TCP/UDP/gRPC Forwarding
sidebar_position: 7
---

# PassThrough (TCP/UDP/gRPC Forwarding)

Goma Gateway supports transparent forwarding of **TCP** and **UDP** traffic through its **PassThrough** entry point. This enables proxying non-HTTP protocols, including gRPC carried over a raw TCP stream, alongside HTTP/S traffic.

Forwarded traffic is copied byte for byte: routes, middlewares, and TLS termination do not apply to it.

---

## TCP/UDP Forwarding Configuration

You can define TCP/UDP forwarding rules under `gateway.entryPoints.passThrough.forwards` by specifying the protocol, listening port, and target backend address.

---

### Configuration Fields

* **`protocol`** (`string`): Protocol to forward. Valid values:

    * `tcp`
    * `udp`
    * `tcp/udp` (both TCP and UDP on the same port)

* **`port`** (`integer`): The port the gateway listens on, on all interfaces, for incoming traffic. It must not be used by another entry point or forward.

* **`target`** (`string`): The backend destination in the format `hostname:port` or `ip:port` where traffic will be forwarded.

Timeouts are not configurable: connecting to the target times out after 10 seconds, and a UDP session is closed after 5 minutes without traffic.

---

### Minimal Example

```yaml
gateway:
  entryPoints:
    passThrough:
      forwards:
        - protocol: tcp
          port: 2222
          target: srv1.example.com:61557
```

---

### Full Example

```yaml
version: 2
gateway:
  entryPoints:
    web:
      address: ":80"       # HTTP server port
    webSecure:
      address: ":443"      # HTTPS server port
    passThrough:
      forwards:
        - protocol: tcp
          port: 61557
          target: srv1.example.com:22
        - protocol: tcp/udp
          port: 53
          target: 10.25.10.15:53
        - protocol: udp
          port: 54
          target: 10.25.10.22:54
```

---

### Notes

* The **passThrough** entry point enables proxying of arbitrary TCP/UDP traffic.
* Use this feature to forward protocols like SSH, DNS, or custom gRPC connections.
* Make sure target services are reachable from the gateway.
* An unknown `protocol` or an invalid `port` stops the gateway at startup.
* Forwards are read at startup only; changing them requires a restart, not a configuration reload.
