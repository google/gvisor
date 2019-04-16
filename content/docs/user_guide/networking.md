+++
title = "Networking"
weight = 50
+++
gVisor implements its own network stack called [netstack][netstack]. All aspects
of the network stack are handled inside the Sentry — including TCP connection
state, control messages, and packet assembly — keeping it isolated from the host
network stack. Data link layer packets are written directly to the virtual
device inside the network namespace setup by Docker or Kubernetes.

The IP address and routes configured for the device are transferred inside the
sandbox. The loopback device runs exclusively inside the sandbox and does not
use the host. You can inspect them by running:

```bash
docker run --rm --runtime=runsc alpine ip addr
```

## Network passthrough

For high-performance networking applications, you may choose to disable the user
space network stack and instead use the host network stack, including the loopback.
Note that this mode decreases the isolation to the host.

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

To completely isolate the host and network from the sandbox, external
networking can be disabled. The sandbox will still contain a loopback provided
by netstack.

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

### Disable GSO {#gso}

If your Linux is older than {{< required_linux >}}, you can disable Generic
Segmentation Offload (GSO) to run with a kernel that is newer than 3.17. Add the
`--gso=false` flag to your Docker runtime configuration (`/etc/docker/daemon.json`)
and restart the Docker daemon:

> Note: Network performance, especially for large payloads, will be greatly reduced.

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

[netstack]: https://github.com/google/netstack
