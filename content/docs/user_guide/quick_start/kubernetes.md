+++
title = "Kubernetes"
weight = 20
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

## Using GKE Sandbox

[GKE Sandbox][gke-sandbox] is available in [Google Kubernetes Engine][gke]. You
just need to deploy a node pool with gVisor enabled in your cluster, and it will
run pods annotated with `runtimeClassName: gvisor` inside a gVisor sandbox for
you. [Here][wordpress-quick] is a quick example showing how to deploy a 
WordPress site. You can view the full documentation [here][gke-sandbox-docs].

[containerd]: https://containerd.io/
[minikube]: https://github.com/kubernetes/minikube/blob/master/deploy/addons/gvisor/README.md
[gke]: https://cloud.google.com/kubernetes-engine/
[gke-sandbox]: https://cloud.google.com/kubernetes-engine/sandbox/
[gke-sandbox-docs]: https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods
[gvisor-containerd-shim]: https://github.com/google/gvisor-containerd-shim
[runtimeclass]: https://kubernetes.io/docs/concepts/containers/runtime-class/
[wordpress-quick]: /docs/tutorials/kubernetes/