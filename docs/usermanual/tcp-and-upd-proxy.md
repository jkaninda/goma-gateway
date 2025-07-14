---
title: TLS & Let's Encrypt
layout: default
parent: User Manual
nav_order: 7
---

# PassThrough (TCP/UDP/gRPC Forwarding)

Goma Gateway supports transparent forwarding of **TCP**, **UDP**, and **gRPC** traffic through its **PassThrough** entry point. This enables proxying non-HTTP protocols alongside HTTP/S traffic.

---

## TCP/UDP Forwarding Configuration

You can define TCP/UDP forwarding rules under the `passThrough` entry point by specifying the protocol, listening port, and target backend address.

---

### Configuration Fields

* **`protocol`** (`string`): Protocol to forward. Valid values:

    * `tcp`
    * `udp`
    * `tcp/udp` (both TCP and UDP on the same port)

* **`port`** (`integer`): The local listening port on the gateway for incoming traffic.

* **`target`** (`string`): The backend destination in the format `hostname:port` or `ip:port` where traffic will be forwarded.

* **`timeout`** (`integer`, optional): Timeout in seconds for establishing or maintaining the connection (default behavior if omitted).

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
          timeout: 5
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
* Timeouts help prevent hanging connections but can be omitted for default behavior.
