# Configure containerd-shim-runsc-v1 (Shim V2)

This document describes how to configure runtime options for `containerd-shim-runsc-v1`.
This is follows on to the instructions of [Runtime Handler Quick Start (shim v2) (containerd >=1.2)](runtime-handler-shim-v2-quickstart.md) and requires containerd 1.3 or later.

## Configuration

`containerd-shim-runsc-v1` supports a few different configuration options based on the version of containerd that is used. For versions >= 1.3, it supports a configurable config path in the containerd runtime configuration.

1. Update `/etc/containerd/config.toml` to point to a configuration file for `containerd-shim-runsc-v1`.

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

2. Configure `/etc/containerd/runsc.toml` with the desired options. The set of options that can be configured can be found in [options.go](../pkg/v2/options/options.go). This example shows how to configure `containerd-shim-runsc-v1` to use gvisor with the kvm platform.

```shell
{ # Step 2: Create containerd-shim-runsc-v1 runtime options config
cat <<EOF | sudo tee /etc/containerd/runsc.toml
[runsc_config]
platform = "kvm"
EOF
}
```

3. Restart `containerd`

```shell
sudo systemctl restart containerd
```
