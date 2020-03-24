# Configure gvisor-containerd-shim (Shim V1)

This document describes how to configure runtime options for `gvisor-containerd-shim`.

The shim configuration is stored in `/etc/containerd/gvisor-containerd-shim.toml`.  The configuration file supports two values.

`runc_shim`: The path to the runc shim. This is used by the gvisor-containerd-shim to run normal containers.
`runsc_config`: This is a set of key/value pairs that are converted into `runsc` command line flags. You can learn more about which flags are available by running `runsc flags`.

## Example: Enable the KVM platform

gVisor enables the use of a number of platforms. This configuration enables the
KVM platform.

Find out more about platform in the
(gVisor documentation)[https://gvisor.dev/docs/user_guide/platforms/].

```shell
cat <<EOF | sudo tee /etc/containerd/gvisor-containerd-shim.toml
[runsc_config]
platform = "kvm"
EOF
```

## Example: Enable gVisor debug logging

gVisor debug logging can be enabled by setting the `debug` and `debug-log`
flag. The shim will replace "%ID%" with the container ID in the path of the
`debug-log` flag.

Find out more about debugging in the
(gVisor documentation)[https://gvisor.dev/docs/user_guide/debugging/].

```shell
cat <<EOF | sudo tee /etc/containerd/gvisor-containerd-shim.toml
# This is the path to the default runc containerd-shim.
runc_shim = "/usr/local/bin/containerd-shim"
[runsc_config]
  debug=true
  debug-log=/var/log/%ID%/gvisor.log
EOF
```
