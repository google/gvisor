# Containerd Advanced Configuration

This document describes how to configure runtime options for
`containerd-shim-runsc-v1`. You can find the installation instructions and
minimal requirements in [Containerd Quick Start](./quick_start.md).

## Shim Configuration

The shim can be provided with a configuration file containing options to the
shim itself as well as a set of flags to runsc. Here is a quick example:

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
option = "value"
[runsc_config]
  flag = "value"
EOF
```

The set of options that can be configured can be found in
[options.go](https://cs.opensource.google/gvisor/gvisor/+/master:pkg/shim/runsc/options.go).
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
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
EOF
```

When you are done, restart containerd to pick up the changes.

```shell
sudo systemctl restart containerd
```

## Debug

When `shim_debug` is enabled in `/etc/containerd/config.toml`, containerd will
forward shim logs to its own log. You can additionally set `level = "debug"` to
enable debug logs. To see the logs run `sudo journalctl -u containerd`. Here is
a containerd configuration file that enables both options:

```shell
cat <<EOF | sudo tee /etc/containerd/config.toml
version = 2
[debug]
  level = "debug"
[plugins."io.containerd.runtime.v1.linux"]
  shim_debug = true
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
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
EOF
```

## NVIDIA Container Runtime

If you want to use
[`nvidia-container-runtime`](https://developer.nvidia.com/container-runtime)
with runsc through containerd, you might need to configure `nvidia` runtime in
containerd via `sudo nvidia-ctk runtime configure --runtime=containerd` command.
This will update `/etc/containerd/config.toml` with a new runtime named
`nvidia`. However, this runtime's configuration is not compatible with runsc:

-   Its `runtime_type` is set to runc. You will need to manually update this
    field to specify runsc so that containerd tries to invoke
    `containerd-shim-runsc-v1` when using `nvidia` runtime.
-   Its `options` attempts to specify `BinaryName =
    "/usr/bin/nvidia-container-runtime"`. However, runsc shim takes
    configuration via `ConfigPath` as shown above. So the `options` needs to be
    updated to specify `ConfigPath` and in the config.toml file needs to specify
    the `BinaryName`.

The `/etc/containerd/config.toml` file should look like:

```
...
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia]
  runtime_type = "io.containerd.runsc.v1"

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
...
```

And `/etc/containerd/runsc.toml` should look something like:

```
log_path = "/var/log/runsc/%ID%/shim.log"
log_level = "debug"
binary_name = "/usr/bin/nvidia-container-runtime"
[runsc_config]
  debug = "true"
  debug-log = "/var/log/runsc/%ID%/gvisor.%COMMAND%.log"
  nvproxy = "true"
```

See [this section](../gpu.md#nvidia-container-runtime) for information about
configuring `nvidia-container-runtime` to use `runsc` as its low-level runtime.
