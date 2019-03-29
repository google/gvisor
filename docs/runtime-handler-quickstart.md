# Runtime Handler Quickstart

This document describes how to install and run the `gvisor-containerd-shim`
using the containerd runtime handler support. This requires containerd 1.2 or
later.

## Requirements

- **runsc**: See the [gVisor documentation](https://github.com/google/gvisor) for information on how to install runsc.
- **containerd**: See the [containerd website](https://containerd.io/) for information on how to install containerd.

## Install

### Install gvisor-containerd-shim

1. Download the latest release of the `gvisor-containerd-shim`. See the
   [releases page](https://github.com/google/gvisor-containerd-shim/releases)

[embedmd]:# (../test/e2e/shim-install.sh shell /{ # Step 1\(release\)/ /^}/)
```shell
{ # Step 1(release): Install gvisor-containerd-shim
LATEST_RELEASE=$(wget -qO - https://api.github.com/repos/google/gvisor-containerd-shim/releases | grep -oP '(?<="browser_download_url": ")https://[^"]*gvisor-containerd-shim.linux-amd64' | head -1)
wget -O gvisor-containerd-shim ${LATEST_RELEASE}
chmod +x gvisor-containerd-shim
sudo mv gvisor-containerd-shim /usr/local/bin/gvisor-containerd-shim
}
```

2. Create the configuration for the gvisor shim in
   `/etc/containerd/gvisor-containerd-shim.toml`:

[embedmd]:# (../test/e2e/shim-install.sh shell /{ # Step 2/ /^}/)
```shell
{ # Step 2: Create the gvisor-containerd-shim.toml
cat <<EOF | sudo tee /etc/containerd/gvisor-containerd-shim.toml
# This is the path to the default runc containerd-shim.
runc_shim = "/usr/local/bin/containerd-shim"
EOF
}
```

### Configure containerd

1. Update `/etc/containerd/config.toml`. Be sure to update the path to
   `gvisor-containerd-shim` and `runsc` if necessary:

[embedmd]:# (../test/e2e/runtime-handler/install.sh shell /{ # Step 1/ /^}/)
```shell
{ # Step 1: Create containerd config.toml
cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
[plugins.linux]
  shim = "/usr/local/bin/gvisor-containerd-shim"
  shim_debug = true
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runtime.v1.linux"
  runtime_engine = "/usr/local/bin/runsc"
  runtime_root = "/run/containerd/runsc"
EOF
}
```

2. Restart `containerd`

```shell
sudo systemctl restart containerd
```

## Usage

You can run containers in gVisor via containerd's CRI.

### Install crictl

1. Download and install the crictl binary:

[embedmd]:# (../test/e2e/crictl-install.sh shell /{ # Step 1/ /^}/)
```shell
{ # Step 1: Download crictl
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.13.0/crictl-v1.13.0-linux-amd64.tar.gz
tar xf crictl-v1.13.0-linux-amd64.tar.gz
sudo mv crictl /usr/local/bin
}
```

2. Write the crictl configuration file

[embedmd]:# (../test/e2e/crictl-install.sh shell /{ # Step 2/ /^}/)
```shell
{ # Step 2: Configure crictl
cat <<EOF | sudo tee /etc/crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
EOF
}
```

### Create the nginx Sandbox in gVisor

1. Pull the nginx image

[embedmd]:# (../test/e2e/runtime-handler/usage.sh shell /{ # Step 1/ /^}/)
```shell
{ # Step 1: Pull the nginx image
sudo crictl pull nginx
}
```

2. Create the sandbox creation request

[embedmd]:# (../test/e2e/runtime-handler/usage.sh shell /{ # Step 2/ /^EOF\n}/)
```shell
{ # Step 2: Create sandbox.json
cat <<EOF | tee sandbox.json
{
    "metadata": {
        "name": "nginx-sandbox",
        "namespace": "default",
        "attempt": 1,
        "uid": "hdishd83djaidwnduwk28bcsb"
    },
    "linux": {
    },
    "log_directory": "/tmp"
}
EOF
}
```

3. Create the pod in gVisor

[embedmd]:# (../test/e2e/runtime-handler/usage.sh shell /{ # Step 3/ /^}/)
```shell
{ # Step 3: Create the sandbox
SANDBOX_ID=$(sudo crictl runp --runtime runsc sandbox.json)
}
```

### Run the nginx Container in the Sandbox

1. Create the nginx container creation request

[embedmd]:# (../test/e2e/run-container.sh shell /{ # Step 1/ /^EOF\n}/)
```shell
{ # Step 1: Create nginx container config
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
}
```

2. Create the nginx container

[embedmd]:# (../test/e2e/run-container.sh shell /{ # Step 2/ /^}/)
```shell
{ # Step 2: Create nginx container
CONTAINER_ID=$(sudo crictl create ${SANDBOX_ID} container.json sandbox.json)
}
```

3. Start the nginx container

[embedmd]:# (../test/e2e/run-container.sh shell /{ # Step 3/ /^}/)
```shell
{ # Step 3: Start nginx container
sudo crictl start ${CONTAINER_ID}
}
```

### Validate the container

1. Inspect the created pod

[embedmd]:# (../test/e2e/validate.sh shell /{ # Step 1/ /^}/)
```shell
{ # Step 1: Inspect the pod
sudo crictl inspectp ${SANDBOX_ID}
}
```

2. Inspect the nginx container

[embedmd]:# (../test/e2e/validate.sh shell /{ # Step 2/ /^}/)
```shell
{ # Step 2: Inspect the container
sudo crictl inspect ${CONTAINER_ID}
}
```

3. Verify that nginx is running in gVisor

[embedmd]:# (../test/e2e/validate.sh shell /{ # Step 3/ /^}/)
```shell
{ # Step 3: Check dmesg
sudo crictl exec ${CONTAINER_ID} dmesg | grep -i gvisor
}
```
