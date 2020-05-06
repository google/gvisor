# Configure containerd-shim-runsc-v1 (Shim V2)

This document describes how to configure runtime options for
`containerd-shim-runsc-v1`.  This is follows on to the instructions of
[Runtime Handler Quick Start (shim v2) (containerd >=1.2)](runtime-handler-shim-v2-quickstart.md)
and requires containerd 1.3 or later.

### Update `/etc/containerd/config.toml` to point to a configuration file for `containerd-shim-runsc-v1`.

`containerd-shim-runsc-v1` supports a few different configuration options based
on the version of containerd that is used. For versions >= 1.3, it supports a
configurable config path in the containerd runtime configuration.

```shell
{ # Step 1: Update runtime options for runsc in containerd config.toml
cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
[plugins.linux]
  shim_debug = true
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
[plugins.cri.containerd.runtimes.runsc.options]
  TypeUrl = "io.containerd.runsc.v1.options"
  ConfigPath = "/etc/containerd/runsc.toml"
EOF
}
```

### Configure `/etc/containerd/runsc.toml`

The set of options that can be configured can be found in
[options.go](../pkg/v2/options/options.go).

#### Example: Enable the KVM platform

gVisor enables the use of a number of platforms. This example shows how to
configure `containerd-shim-runsc-v1` to use gvisor with the KVM platform.

Find out more about platform in the
(gVisor documentation)[https://gvisor.dev/docs/user_guide/platforms/].

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
[runsc_config]
platform = "kvm"
EOF
```

### Example: Enable gVisor debug logging

gVisor debug logging can be enabled by setting the `debug` and `debug-log`
flag. The shim will replace "%ID%" with the container ID in the path of the
`debug-log` flag.

Find out more about debugging in the
(gVisor documentation)[https://gvisor.dev/docs/user_guide/debugging/].

```shell
cat <<EOF | sudo tee /etc/containerd/runsc.toml
[runsc_config]
  debug=true
  debug-log=/var/log/%ID%/gvisor.log
EOF
```

## Restart `containerd`

When you are done restart containerd to pick up the new configuration files.

```shell
sudo systemctl restart containerd
```
