# Runtime Handler Quickstart (Shim V2)

This document describes how to install and run `containerd-shim-runsc-v1` using
the containerd runtime handler support. This requires containerd 1.2 or later.

## Requirements

- **runsc**: See the [gVisor documentation](https://github.com/google/gvisor) for information on how to install runsc.
- **containerd**: See the [containerd website](https://containerd.io/) for information on how to install containerd.

## Install

### Install containerd-shim-runsc-v1

1. Build and install `containerd-shim-runsc-v1`.

<!-- TODO: Use a release once we have one available. -->
[embedmd]:# (../test/e2e/shim-install.sh shell /{ # Step 1\(dev\)/ /^}/)
```shell
{ # Step 1(dev): Build and install gvisor-containerd-shim and containerd-shim-runsc-v1
    make
    sudo make install
}
```

### Configure containerd

1. Update `/etc/containerd/config.toml`. Make sure `containerd-shim-runsc-v1` is
   in `${PATH}`.

[embedmd]:# (../test/e2e/runtime-handler-shim-v2/install.sh shell /{ # Step 1/ /^}/)
```shell
{ # Step 1: Create containerd config.toml
cat <<EOF | sudo tee /etc/containerd/config.toml
disabled_plugins = ["restart"]
[plugins.linux]
  shim_debug = true
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
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
