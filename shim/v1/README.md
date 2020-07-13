# gvisor-containerd-shim

> Note: This shim version is supported only for containerd versions less than
> 1.2. If you are using a containerd version greater than or equal to 1.2, then
> please use `containerd-shim-runsc-v1` (Shim API v1).
>
> This containerd shim is supported only in a best-effort capacity.

This document describes how to configure and use `gvisor-containerd-shim`.

## Containerd Configuration

To use this shim, you must configure `/etc/containerd/config.toml` as follows:

```
[plugins.linux]
  shim = "/usr/bin/gvisor-containerd-shim"
[plugins.cri.containerd.runtimes.gvisor]
  runtime_type = "io.containerd.runtime.v1.linux"
  runtime_engine = "/usr/bin/runsc"
  runtime_root = "/run/containerd/runsc"
```

In order to pick-up the new configuration, you may need to restart containerd:

```shell
sudo systemctl restart containerd
```

## Shim Confguration

The shim configuration is stored in `/etc/containerd/runsc.toml`. The
configuration file supports two values.

*   `runc_shim`: The path to the runc shim. This is used by
    `gvisor-containerd-shim` to run standard containers.

*   `runsc_config`: This is a set of key/value pairs that are converted into
    `runsc` command line flags. You can learn more about which flags are
    available by running `runsc flags`.

For example, a configuration might look as follows:

```
runc_shim = "/usr/local/bin/containerd-shim"
[runsc_config]
platform = "kvm"
debug = true
debug-log = /var/log/%ID%/gvisor/
```
