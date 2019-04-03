+++
title = "Kubernetes"
weight = 30
+++
gVisor can be used to run Kubernetes pods and has several integration points
with Kubernetes.

## Using Minikube

gVisor can run sandboxed containers in a Kubernetes cluster with Minikube.
After the gVisor addon is enabled, pods with
`io.kubernetes.cri.untrusted-workload` set to true will execute with `runsc`.
Follow [these instructions][minikube] to enable gVisor addon.

## Using Containerd

You can also setup Kubernetes nodes to run pods in gvisor using the
[containerd][containerd] CRI runtime and the `gvisor-containerd-shim`. You can
use either the `io.kubernetes.cri.untrusted-workload` annotation or
[RuntimeClass][runtimeclass] to run Pods with `runsc`. You can find
instructions [here][gvisor-containerd-shim].

[containerd]: https://containerd.io/
[minikube]: https://github.com/kubernetes/minikube/blob/master/deploy/addons/gvisor/README.md
[gvisor-containerd-shim]: https://github.com/google/gvisor-containerd-shim
[runtimeclass]: https://kubernetes.io/docs/concepts/containers/runtime-class/
