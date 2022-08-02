# Kubernetes Quick Start

gVisor can be used to run Kubernetes pods and has several integration points
with Kubernetes.

## Using GKE Sandbox

[GKE Sandbox][gke-sandbox] is available in [Google Kubernetes Engine][gke]. You
just need to deploy a node pool with gVisor enabled in your cluster, and it will
run pods annotated with `runtimeClassName: gvisor` inside a gVisor sandbox for
you. [Here][wordpress-quick] is a quick example showing how to deploy a
WordPress site. You can view the full documentation [here][gke-sandbox-docs].

## Using Minikube

gVisor can run sandboxed containers in a Kubernetes cluster with Minikube. After
the gVisor addon is enabled, pods with a `gvisor` [Runtime Class][runtimeclass]
set to true will execute with `runsc`. Follow [these instructions][minikube] to
enable gVisor addon.

## Using Containerd

You can also setup Kubernetes nodes to run pods in gVisor using
[containerd][containerd] and the gVisor containerd shim. You can find
instructions in the [Containerd Quick Start][gvisor-containerd].

[containerd]: https://containerd.io/
[minikube]: https://github.com/kubernetes/minikube/blob/master/deploy/addons/gvisor/README.md
[gke]: https://cloud.google.com/kubernetes-engine/
[gke-sandbox]: https://cloud.google.com/kubernetes-engine/sandbox/
[gke-sandbox-docs]: https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods
[gvisor-containerd]: /docs/user_guide/containerd/quick_start/
[runtimeclass]: https://kubernetes.io/docs/concepts/containers/runtime-class/
[wordpress-quick]: /docs/tutorials/kubernetes/
