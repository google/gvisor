# Containerd Quick Start

This document describes how to use `containerd-shim-runsc-v1` with the
containerd runtime handler support on `containerd`. This is a similar setup as
[GKE Sandbox], other than the
[platform configuration](/docs/architecture_guide/platforms/).

> ⚠️ **Note**: If you are using Kubernetes and set up your cluster using
> `kubeadm` you may run into issues. See the [FAQ](../FAQ.md#runtime-handler)
> for details.

## Requirements

-   **runsc** and **containerd-shim-runsc-v1**: See the
    [installation guide](/docs/user_guide/install/).
-   **containerd**: See the [containerd website](https://containerd.io/) for
    information on how to install containerd. **Minimal version supported: 1.3.9
    or 1.4.3.**

## Configure containerd

Update `/etc/containerd/config.toml`. Make sure `containerd-shim-runsc-v1` is in
`${PATH}` or in the same directory as `containerd` binary.

```shell
cat <<EOF | sudo tee /etc/containerd/config.toml
version = 2
[plugins."io.containerd.runtime.v1.linux"]
  shim_debug = true
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF
```

> Consider using the version header `version = 3` if you are using containerd
> 2.x. See the difference at
> [containerd version header](https://github.com/containerd/containerd/blob/v2.0.2/docs/PLUGINS.md#version-header)

### Install CNI plugins

Typically, you will have to install CNI plugins to complete the following steps.

For the quick start, it is sufficient to install the plugins with default
settings by running the script from the containerd project:

```shell
git clone --depth=1 -b {CONTAINERD_VERSION} https://github.com/containerd/containerd.git
cd containerd && ./script/setup/install-cni
```

### Restart `containerd`

```shell
sudo systemctl restart containerd
```

## Usage

You can run containers in gVisor via [ctr] or [crictl].

[ctr]: https://github.com/projectatomic/containerd/blob/master/docs/cli.md
[crictl]: https://github.com/kubernetes-sigs/cri-tools/blob/master/docs/crictl.md

### ctr

The tool `ctr` communicates directly with containerd, and it is a part of each
containerd release.

#### Running a container

Now run your container using the runsc runtime:

```shell
sudo ctr image pull docker.io/library/hello-world:latest
sudo ctr run --runtime io.containerd.runsc.v1 -t --rm docker.io/library/hello-world:latest hello-wrold
```

#### Verify the runtime

You can verify that you are running in gVisor using the dmesg command.

```shell
$ sudo ctr image pull docker.io/library/busybox:latest
$ sudo ctr run --runtime io.containerd.run.runsc.v1 -t --rm docker.io/library/busybox:latest gvisord dmesg
[   0.000000] Starting gVisor...
[   0.445958] Forking spaghetti code...
[   0.794963] Feeding the init monster...
[   0.842573] Synthesizing system calls...
[   0.985066] Generating random numbers by fair dice roll...
[   1.444465] Mounting deweydecimalfs...
[   1.546130] Waiting for children...
[   1.689078] Searching for socket adapter...
[   2.026282] Accelerating teletypewriter to 9600 baud...
[   2.274752] Creating process schedule...
[   2.498083] Reticulating splines...
[   2.675603] Setting up VFS...
[   2.750186] Setting up FUSE...
[   2.789133] Ready!
```

### crictl

Alternatively, you can use crictl which designed for CRI-compatible containers.

#### Install crictl

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

#### Create the nginx sandbox in gVisor

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
    "linux": {
    },
    "log_directory": "/tmp"
}
EOF
```

Create the pod in gVisor:

```shell
SANDBOX_ID=$(sudo crictl runp --runtime runsc sandbox.json)
```

#### Run the nginx container in the sandbox

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

#### Validate the container

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

#### Set up the Kubernetes RuntimeClass

Install the RuntimeClass for gVisor:

```shell
cat <<EOF | kubectl apply -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
```

Create a Pod with the gVisor RuntimeClass:

```shell
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: nginx-gvisor
spec:
  runtimeClassName: gvisor
  containers:
  - name: nginx
    image: nginx
EOF
```

Verify that the Pod is running:

```shell
kubectl get pod nginx-gvisor -o wide
```

### What's next

This setup is already done for you on [GKE Sandbox]. It is an easy way to get
started with gVisor.

Before taking this deployment to production, review the
[Production guide](/docs/user_guide/production/).

[GKE Sandbox]: https://cloud.google.com/kubernetes-engine/docs/concepts/sandbox-pods
