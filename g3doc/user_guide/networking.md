# Networking

[TOC]

gVisor implements its own network stack called [netstack][netstack]. All aspects
of the network stack are handled inside the Sentry — including TCP connection
state, control messages, and packet assembly — keeping it isolated from the host
network stack. Data link layer packets are written directly to the virtual
device inside the network namespace setup by Docker or Kubernetes.

Configuring the network stack may provide performance benefits, but isn't the
only step to optimizing gVisor performance. See the
[Production guide][Production guide] for more.

The IP address and routes configured for the device are transferred inside the
sandbox. The loopback device runs exclusively inside the sandbox and does not
use the host. You can inspect them by running:

```bash
docker run --rm --runtime=runsc alpine ip addr
```

## Network passthrough

For high-performance networking applications, you may choose to disable the user
space network stack and instead use the host network stack, including the
loopback. Note that this mode decreases the isolation to the host.

Add the following `runtimeArgs` to your Docker configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network=host"
            ]
       }
    }
}
```

## Disabling external networking

To completely isolate the host and network from the sandbox, external networking
can be disabled. The sandbox will still contain a loopback provided by netstack.

Add the following `runtimeArgs` to your Docker configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network=none"
            ]
       }
    }
}
```

## External network proxy (experimental)

Instead of writing packets to the virtual device with an `AF_PACKET` socket, the
sandbox's primary network interface can be attached to a `SOCK_SEQPACKET` unix
domain socket owned by an external process. The sentry writes IP packets and the
external peer is responsible for proxying those packets onward. This works only
with `network=sandbox` mode and L4 network proxies.

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network-proxy-path=/run/netproxy.sock"
            ]
       }
    }
}
```

Inside the sandbox, `runsc` still scrapes the container's network namespace and
configures netstack with the same interface names, MTUs, IPv4/IPv6 addresses,
and routes (including default gateways). The primary interface is chosen from
the default gateway's interface (or `eth0` / the sole non-loopback interface if
no default route is configured) and is backed by a single-channel `fdbased` link
endpoint over the connected `SOCK_SEQPACKET` socket. Even with `--software-gso`
enabled, netstack segments packets to the link MTU before writing to the socket,
so the peer's read buffer must be at least that MTU.

The peer must already be listening when the sandbox starts, runsc dials the
socket once with timeout for 5 seconds and fails sandbox creation if the
connection cannot be established.

The external peer is responsible for any egress filtering. Only the primary
interface (which carries the default route) is proxied and keeps its host IP
addresses; any other non-loopback interfaces still use `AF_PACKET` sockets (with
host addresses removed) and bypass the proxy.

## Egress traffic shaping (TBF)

gVisor can rate limit outbound sandbox traffic with a
[Token Bucket Filter (TBF)][tc-tbf] queueing discipline. TBF is modeled after
Linux's `tbf` qdisc and supports a single-rate bucket. It applies to
non-loopback NICs when using netstack; ingress and loopback traffic are not
shaped. The implementation lives in [pkg/tcpip/link/qdisc/tbf][tbf-source].

To enable TBF globally, add the following `runtimeArgs` to your Docker
configuration (`/etc/docker/daemon.json`) and restart the Docker daemon. For
example, 100 Mbps is 12,500,000 bytes/sec:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network=sandbox",
                "--qdisc=tbf",
                "--qdisc-tbf-rate=12500000",
                "--qdisc-tbf-burst=1048576"
            ]
       }
    }
}
```

`--qdisc=tbf` selects TBF instead of the default FIFO qdisc. `--qdisc-tbf-rate`
is the sustained egress rate in bytes/sec. `--qdisc-tbf-burst` is the bucket
depth in bytes. After an idle period, up to `qdisc-tbf-burst` bytes can transmit
at line rate before throttling engages; sustained throughput is bounded by
`qdisc-tbf-rate`. Both flags take plain integers; unlike Linux `tc(8)`, gVisor
does not accept unit-suffixed strings like `1mbit` or `1mbps`. Both
`--qdisc-tbf-rate` and `--qdisc-tbf-burst` are required when `--qdisc=tbf`; the
sandbox refuses to start otherwise. There is no universal default for either:
rate is policy and burst depends on the workload's MTU, GSO configuration, and
acceptable latency.

Per-sandbox overrides can be set via OCI runtime annotations from any client
that supports them, including Kubernetes pod annotations propagated by
containerd, Docker (`--annotation key=value`), podman, and a raw OCI bundle's
`config.json`. The relevant keys are:

```
dev.gvisor.flag.qdisc: "tbf"
dev.gvisor.flag.qdisc-tbf-rate: "12500000"
dev.gvisor.flag.qdisc-tbf-burst: "1048576"
```

For example, on a Kubernetes pod:

```yaml
metadata:
  annotations:
    dev.gvisor.flag.qdisc: "tbf"
    dev.gvisor.flag.qdisc-tbf-rate: "12500000"
    dev.gvisor.flag.qdisc-tbf-burst: "1048576"
```

The `qdisc` annotation can only select TBF unless `--allow-flag-override` is
enabled; selecting `fifo` or `none` by annotation is rejected. The
`qdisc-tbf-rate` and `qdisc-tbf-burst` annotations can only lower or match the
runtime-configured values unless `--allow-flag-override` is enabled.

Operators using containerd can set per-runtime ceilings in the containerd
runtime configuration that annotations cannot exceed:

```toml
[runsc_config]
  qdisc-tbf-rate = "12500000"
  qdisc-tbf-burst = "1048576"
```

### Disable GSO {#gso}

If your Linux is older than 4.14.77, you can disable Generic Segmentation
Offload (GSO) to run with a kernel that is newer than 3.17. Add the
`--gso=false` flag to your Docker runtime configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

> Note: Network performance, especially for large payloads, will be greatly
> reduced.

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--gso=false"
            ]
       }
    }
}
```

[netstack]: /docs/architecture_guide/networking/
[Production guide]: /docs/user_guide/production/
[tbf-source]: https://cs.opensource.google/gvisor/gvisor/+/master:pkg/tcpip/link/qdisc/tbf/
[tc-tbf]: https://www.man7.org/linux/man-pages/man8/tc-tbf.8.html
