# CRI-O Quick Start

This document describes how to use `containerd-shim-runsc-v1` with
[CRI-O](https://cri-o.io/) as the container runtime interface.

## Requirements

-   **runsc** and **containerd-shim-runsc-v1**: See the
    [installation guide](/docs/user_guide/install/).
-   **CRI-O**: See the [CRI-O installation guide](https://github.com/cri-o/cri-o/blob/main/install.md).
    **Minimal version supported: v1.37.**
-   **CNI plugins**: Required for pod networking. Install via your distribution
    package manager (e.g. `containernetworking-plugins` on Fedora,
    `containernetworking-plugins` on Ubuntu/Debian).

## Configure the shim

Create `/etc/containerd/runsc.toml` with the following content:

```toml
binary_name = "/usr/local/bin/runsc"

# grouping must be true so that sub-containers (app containers) attach to the
# sandbox shim started for the pause container, rather than starting their own.
grouping = true

[runsc_config]
  platform  = "systrap"
  network   = "sandbox"
  debug     = "true"
  debug-log = "/var/log/runsc/%ID%.log"
```

-   `binary_name`: path to the `runsc` binary. This is distinct from the shim
    binary path configured in CRI-O below.
-   `grouping = true`: required for Kubernetes-style pod semantics. Without it,
    each container launches an independent shim that cannot find the sandbox,
    causing container start failures.
-   `platform`: `systrap` is recommended for most environments. See
    [Platforms](/docs/architecture_guide/platforms/) for alternatives.
-   `network = "sandbox"`: enables pod-level networking so all containers in a
    pod share the same network namespace.

## Configure CRI-O

Create a drop-in configuration file `/etc/crio/crio.conf.d/99-gvisor.conf`:

```toml
[crio.runtime]
selinux = false

# runtime_type = "vm" instructs CRI-O to create a pause (infra) container for
# the sandbox. gVisor requires this container to exist before app containers
# are started. Without it, CRI-O skips sandbox creation and the pod fails.
[crio.runtime.runtimes.runsc]
runtime_path        = "/usr/local/bin/containerd-shim-runsc-v1"
runtime_config_path = "/etc/containerd/runsc.toml"
runtime_type        = "vm"
runtime_root        = "/run/runsc"
```

-   `selinux = false`: required when running gVisor. gVisor manages its own
    isolation and does not support SELinux labels on its containers; leaving
    SELinux enabled causes container creation to fail.
-   `runtime_type = "vm"`: the key setting. It tells CRI-O that this runtime
    uses the VM shim model, which ensures the pause container (sandbox) is
    created before any app containers are started.
-   `runtime_path`: path to `containerd-shim-runsc-v1`, which must follow the
    `containerd-shim-<name>-v1` naming convention.
-   `runtime_config_path`: path to the shim configuration file created above.
-   `runtime_root`: directory where runsc stores sandbox state.

### CNI plugin path

CRI-O's default CNI plugin search path may not match your distribution. If pods
fail to start with a CNI error, configure the path explicitly:

```toml
# Fedora / RHEL (containernetworking-plugins installs to /usr/libexec/cni/)
[crio.network]
plugin_dirs = ["/usr/libexec/cni/", "/opt/cni/bin/"]
```

```toml
# Ubuntu / Debian (plugins typically install to /opt/cni/bin/)
[crio.network]
plugin_dirs = ["/opt/cni/bin/"]
```

## Restart CRI-O

```shell
sudo systemctl restart crio
```

## Usage

You can run gVisor sandboxes through CRI-O using [crictl].

[crictl]: https://github.com/kubernetes-sigs/cri-tools/blob/master/docs/crictl.md

### Configure crictl

```shell
cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///var/run/crio/crio.sock
EOF
```

### Create a sandbox

```shell
cat <<EOF | tee sandbox.json
{
    "metadata": {
        "name": "nginx-sandbox",
        "namespace": "default",
        "attempt": 1,
        "uid": "hdishd83djaidwnduwk28bcsb"
    },
    "linux": {},
    "log_directory": "/tmp"
}
EOF

SANDBOX_ID=$(sudo crictl runp --runtime runsc sandbox.json)
```

### Run a container in the sandbox

```shell
cat <<EOF | tee container.json
{
  "metadata": { "name": "nginx" },
  "image": { "image": "nginx" },
  "log_path": "nginx.0.log",
  "linux": {}
}
EOF

CONTAINER_ID=$(sudo crictl create ${SANDBOX_ID} container.json sandbox.json)
sudo crictl start ${CONTAINER_ID}
```

### Verify the runtime

```shell
sudo crictl exec ${CONTAINER_ID} dmesg | grep -i gvisor
```

### Set up the Kubernetes RuntimeClass

```shell
cat <<EOF | kubectl apply -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
```

## Debug

See the [debugging guide](/docs/user_guide/debugging/) for general guidance.
Shim logs are written to the path specified by `debug-log` in `runsc.toml`. CRI-O
daemon logs are available via:

```shell
sudo journalctl -u crio
```
