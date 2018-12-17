# gvisor-containerd-shim

gvisor-containerd-shim is a containerd shim for [gVisor](https://github.com/google/gvisor/). It implements the containerd v1 shim API. It can be used as a drop-in replacement for [containerd-shim](https://github.com/containerd/containerd/tree/master/cmd/containerd-shim) (though containerd-shim must still be installed). It allows the use of both gVisor (runsc) and normal containers in the same containerd installation by deferring to the runc shim if the desired runtime engine is not runsc.

## Requirements

- gvisor (runsc) >= a2ad8fe
- containerd, containerd-shim >= 1.1

## Installation

1. Download the latest release of the gvisor-containerd-shim and unpack the binary to the desired directory:

```
$ tar xf gvisor-containerd-shim.tar.gz
$ mv gvisor-containerd-shim /usr/local/bin
```

2. Create the configuration for the gvisor shim in `/etc/containerd/gvisor-containerd-shim.yaml`:

```
# This is the path to the default runc containerd-shim.
runc_shim = "/path/to/containerd-shim"
```

3. Update `/etc/containerd/config.toml`. Be sure to update the path to `gvisor-containerd-shim` and `runsc` if necessary:

```
disabled_plugins = ["restart"]
[plugins.linux]
  shim = "/usr/local/bin/gvisor-containerd-shim"
  shim_debug = true
# Uncomment the following 2 lines if you want runsc to be the default runtime.
#  runtime = "/usr/local/bin/runsc"
#  runtime_root = "/run/containerd/runsc"
# To support the untrusted-workload annotation.
[plugins.cri.containerd.untrusted_workload_runtime]
  runtime_type = "io.containerd.runtime.v1.linux"
  runtime_engine = "/usr/local/bin/runsc"
  runtime_root = "/run/containerd/runsc"
[plugins.cri.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runtime.v1.linux"
  runtime_engine = "/usr/local/bin/runsc"
  runtime_root = "/run/containerd/runsc"
```

4. Restart `containerd`

## Usage

### CRI

You can run containers in gVisor via containerd's CRI.

1. Build and install crictl from HEAD:

```
$ go get github.com/kubernetes-sigs/cri-tools/cmd/crictl
$ sudo sh -c 'echo "runtime-endpoint: unix:///run/containerd/containerd.sock" > /etc/crictl.yaml'
```

2. Pull the busybox image

```
$ sudo crictl pull busybox
```

### Containerd 1.1

If running containerd 1.1 you will need to invoke `runsc` via the `io.kubernetes.cri.untrusted-workload` annotation.

1. Create a pod config:

```
$ cat > sandbox.json << EOL
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
EOL
```

2. Run a sandbox with the `runsc` runtime.

```
$ sudo crictl runp sandbox.json
```

### Containerd 1.2

If running containerd 1.2 you can specify runsc as the runtime using the new runtime handler.

1. Create a pod config:

```
$ cat > sandbox.json << EOL
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
EOL
```

2. Run a sandbox with the `runsc` runtime.

```
$ sudo crictl runp --runtime=runsc sandbox.json
```
