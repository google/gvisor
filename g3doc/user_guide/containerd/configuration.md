# Containerd Advanced Configuration

This document describes how to configure runtime options for
`containerd-shim-runsc-v1`. This follows the
[Containerd Quick Start](./quick_start.md) and requires containerd 1.2 or later.

### Update `/etc/containerd/config.toml` to point to a configuration file for `containerd-shim-runsc-v1`.

`containerd-shim-runsc-v1` supports a few different configuration options based
on the version of containerd that is used. For versions >= 1.3, it supports a
configurable `ConfigPath` in the containerd runtime configuration.

```shell
cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
[plugins.linux]
  shim_debug = true
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins.cri.containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  # containerd 1.3 only!
  ConfigPath = "/etc/containerd/runsc.toml"
EOF
```

When you are done restart containerd to pick up the new configuration files.

```shell
sudo systemctl restart containerd
```

### Configure `/etc/containerd/runsc.toml`

> Note: For containerd 1.2, the config file should named `config.toml` and
> located in the runtime root. By default, this is `/run/containerd/runsc`.

The set of options that can be configured can be found in
[options.go](https://github.com/google/gvisor/blob/master/pkg/shim/v2/options.go).

#### Example: Enable the KVM platform

gVisor enables the use of a number of platforms. This example shows how to
configure `containerd-shim-runsc-v1` to use gvisor with the KVM platform.

Find out more about platform in the
[Platforms Guide](../../architecture_guide/platforms.md).

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
[runsc_config]
platform = "kvm"
EOF
```

### Example: Enable gVisor debug logging

gVisor debug logging can be enabled by setting the `debug` and `debug-log` flag.
The shim will replace "%ID%" with the container ID, and "%COMMAND%" with the
runsc command (run, boot, etc.) in the path of the `debug-log` flag.

Find out more about debugging in the [debugging guide](../debugging.md).

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
[runsc_config]
  debug=true
  debug-log=/var/log/%ID%/gvisor.%COMMAND%.log
EOF
```
