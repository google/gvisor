+++
title = "Networking"
weight = 50
+++
gVisor implements its own network stack called [netstack][netstack]. All aspects
of the network stack are handled inside the Sentry — including TCP connection
state, control messages, and packet assembly — keeping it isolated from the host
network stack. Data link layer packets are written directly to the virtual
device inside the network namespace setup by Docker or Kubernetes.

A network passthrough mode is also supported, but comes at the cost of reduced
isolation.

## Enabling network passthrough

For high-performance networking applications, you may choose to disable the user
space network stack and instead use the host network stack. Note that this mode
decreases the isolation to the host.

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

[netstack]: https://github.com/google/netstack
