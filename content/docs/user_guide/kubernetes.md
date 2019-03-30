+++
title = "Kubernetes"
weight = 30
+++
gVisor can run sandboxed containers in a Kubernetes cluster with Minikube. After
the gVisor addon is enabled, pods with `io.kubernetes.cri.untrusted-workload`
set to true will execute with `runsc`. Follow [these instructions][minikube] to
enable gVisor addon.

You can also setup Kubernetes nodes to run pods in gvisor using the `containerd`
CRI runtime and the `gvisor-containerd-shim`. Pods with the
`io.kubernetes.cri.untrusted-workload` annotation will execute with `runsc`. You
can find instructions [here][gvisor-containerd-shim].

[minikube]: https://github.com/kubernetes/minikube/blob/master/deploy/addons/gvisor/README.md
[gvisor-containerd-shim]: https://github.com/google/gvisor-containerd-shim
