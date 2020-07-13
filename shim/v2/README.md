# containerd-shim-runsc-v1

> Note: This shim version is the recommended shim for containerd versions
> greater than or equal to 1.2. For older versions of containerd, use
> `gvisor-containerd-shim`.

This document describes how to configure and use `containerd-shim-runsc-v1`.

## Configuring Containerd 1.2

To configure containerd 1.2 to use this shim, add the runtime to
`/etc/containerd/config.toml` as follows:

```
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
  runtime_root = "/run/containerd/runsc"
[plugins.cri.containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
```

The configuration will optionally loaded from a file named `config.toml` in the
`runtime_root` configured above.

In order to pick up the new configuration, you may need to restart containerd:

```shell
sudo systemctl restart containerd
```

## Configuring Containerd 1.3 and above

To configure containerd 1.3 to use this shim, add the runtime to
`/etc/containerd/config.toml` as follows:

```
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins.cri.containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
```

The `ConfigPath` above will be used to provide a pointer to the configuration
file to be loaded.

> Note that there will be configuration file loaded if `ConfigPath` is not set.

In order to pick up the new configuration, you may need to restart containerd:

```shell
sudo systemctl restart containerd
```

## Shim Confguration

The shim configuration may carry the following options:

*   `shim_cgroup`: The cgroup to use for the shim itself.
*   `io_uid`: The UID to use for pipes.
*   `ui_gid`: The GID to use for pipes.
*   `binary_name`: The runtime binary name (defaults to `runsc`).
*   `root`: The root directory for the runtime.
*   `runsc_config`: A dictionary of key-value pairs that will be passed to the
    runtime as arguments.

### Example: Enable the KVM platform

gVisor enables the use of a number of platforms. This example shows how to
configure `containerd-shim-runsc-v1` to use gVisor with the KVM platform:

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
[runsc_config]
platform = "kvm"
EOF
```

### Example: Enable gVisor debug logging

gVisor debug logging can be enabled by setting the `debug` and `debug-log` flag.
The shim will replace "%ID%" with the container ID in the path of the
`debug-log` flag.

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
[runsc_config]
debug = true
debug-log = /var/log/%ID%/gvisor.log
EOF
```
