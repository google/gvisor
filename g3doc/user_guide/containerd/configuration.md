# Containerd Advanced Configuration

This document describes how to configure runtime options for
`containerd-shim-runsc-v1`. This follows the
[Containerd Quick Start](./quick_start.md) and requires containerd 1.2 or later.

## Shim Configuration

The shim can be provided with a configuration file containing options to the
shim itself as well as a set of flags to runsc. Here is a quick example:

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
option = "value"
[runsc_config]
  flag = "value"
```

The set of options that can be configured can be found in
[options.go](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/shim/options.go).
Values under `[runsc_config]` can be used to set arbitrary flags to runsc.
`flag = "value"` is converted to `--flag="value"` when runsc is invoked. Run
`runsc flags` so see which flags are available

Next, containerd needs to be configured to send the configuration file to the
shim.

### Containerd 1.3+

Starting in 1.3, containerd supports a configurable `ConfigPath` in the runtime
configuration. Here is an example:

```shell
cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins.cri.containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
EOF
```

When you are done, restart containerd to pick up the changes.

```shell
sudo systemctl restart containerd
```

### Containerd 1.2

For containerd 1.2, the config file is not configurable. It should be named
`config.toml` and located in the runtime root. By default, this is
`/run/containerd/runsc`.

### Example: Enable the KVM platform

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

## Debug

When `shim_debug` is enabled in `/etc/containerd/config.toml`, containerd will
forward shim logs to its own log. You can additionally set `level = "debug"` to
enable debug logs. To see the logs run `sudo journalctl -u containerd`. Here is
a containerd configuration file that enables both options:

```shell
cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
[debug]
  level = "debug"
[plugins.linux]
  shim_debug = true
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins.cri.containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
EOF
```

It can be hard to separate containerd messages from the shim's though. To create
a log file dedicated to the shim, you can set the `log_path` and `log_level`
values in the shim configuration file:

-   `log_path` is the directory where the shim logs will be created. `%ID%` is
    the path is replaced with the container ID.
-   `log_level` sets the logs level. It is normally set to "debug" as there is
    not much interesting happening with other log levels.

### Example: Enable shim and gVisor debug logging

gVisor debug logging can be enabled by setting the `debug` and `debug-log` flag.
The shim will replace "%ID%" with the container ID, and "%COMMAND%" with the
runsc command (run, boot, etc.) in the path of the `debug-log` flag.

Find out more about debugging in the [debugging guide](../debugging.md).

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
log_path = "/var/log/runsc/%ID%/shim.log"
log_level = "debug"
[runsc_config]
  debug = "true"
  debug-log = "/var/log/runsc/%ID%/gvisor.%COMMAND%.log"
```
