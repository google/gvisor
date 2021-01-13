# Older Versions (containerd 1.1)

**WARNING: containerd 1.1 and shim v1 is no longer supported. The instructions
below is kept just for reference in case you're dealing with an old version.
It's highly recommended upgrading to the latest version.**

This document describes how to install and run the `gvisor-containerd-shim`
using the untrusted workload CRI extension. This requires `containerd` 1.1 or
later.

*Note: The untrusted workload CRI extension is deprecated by containerd and
`gvisor-containerd-shim` is maintained on a best-effort basis. If you are using
containerd 1.2+, please see the
[containerd 1.2+ documentation](./quick_start.md) and use
`containerd-shim-runsc-v1`.*

## Requirements

-   **runsc** and **gvisor-containerd-shim**: See the
    [installation guide](/docs/user_guide/install/).
-   **containerd**: See the [containerd website](https://containerd.io/) for
    information on how to install containerd.

## Configure containerd

Create the configuration for the gvisor shim in
`/etc/containerd/gvisor-containerd-shim.toml`:

```shell
cat <<EOF | sudo tee /etc/containerd/gvisor-containerd-shim.toml
# This is the path to the default runc containerd-shim.
runc_shim = "/usr/local/bin/containerd-shim"
EOF
```

Update `/etc/containerd/config.toml`. Be sure to update the path to
`gvisor-containerd-shim` and `runsc` if necessary:

```shell
cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
[plugins.linux]
  shim = "/usr/local/bin/gvisor-containerd-shim"
  shim_debug = true
[plugins.cri.containerd.untrusted_workload_runtime]
  runtime_type = "io.containerd.runtime.v1.linux"
  runtime_engine = "/usr/local/bin/runsc"
  runtime_root = "/run/containerd/runsc"
EOF
```

Restart `containerd`:

```shell
sudo systemctl restart containerd
```

## Usage

You can run containers in gVisor via containerd's CRI.

### Install crictl

Download and install the `crictl` binary:

```shell
{
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.13.0/crictl-v1.13.0-linux-amd64.tar.gz
tar xf crictl-v1.13.0-linux-amd64.tar.gz
sudo mv crictl /usr/local/bin
}
```

Write the `crictl` configuration file:

```shell
cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF
```

### Create the nginx Sandbox in gVisor

Pull the nginx image:

```shell
sudo crictl pull nginx
```

Create the sandbox creation request:

```shell
cat <<EOF | tee sandbox.json
{
    "metadata": {
        "name": "nginx-sandbox",
        "namespace": "default",
        "attempt": 1,
        "uid": "hdishd83djaidwnduwk28bcsb"
    },
    "annotations": {
      "io.kubernetes.cri.untrusted-workload": "true"
    },
    "linux": {
    },
    "log_directory": "/tmp"
}
EOF
```

Create the pod in gVisor:

```shell
SANDBOX_ID=$(sudo crictl runp sandbox.json)
```

### Run the nginx Container in the Sandbox

Create the nginx container creation request:

```shell
cat <<EOF | tee container.json
{
  "metadata": {
      "name": "nginx"
    },
  "image":{
      "image": "nginx"
    },
  "log_path":"nginx.0.log",
  "linux": {
  }
}
EOF
```

Create the nginx container:

```shell
CONTAINER_ID=$(sudo crictl create ${SANDBOX_ID} container.json sandbox.json)
```

Start the nginx container:

```shell
sudo crictl start ${CONTAINER_ID}
```

### Validate the container

Inspect the created pod:

```shell
sudo crictl inspectp ${SANDBOX_ID}
```

Inspect the nginx container:

```shell
sudo crictl inspect ${CONTAINER_ID}
```

Verify that nginx is running in gVisor:

```shell
sudo crictl exec ${CONTAINER_ID} dmesg | grep -i gvisor
```
