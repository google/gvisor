# gVisor Kubernetes tool

This tool is meant to make deploying `runsc` in a Kubernetes cluster easier.

## Usage

```shell
# Install using default kubectl context:
$ ./gvisor_k8s_tool install --cluster=kube: --image=my-runsc-installer

# Install using custom kubectl config and context:
$ KUBECONFIG=/tmp/myconfig ./gvisor_k8s_tool \
    install --cluster=kube:mycontext --image=my-runsc-installer

# Install in a GKE cluster:
$ ./gvisor_k8s_tool install \
    --cluster=gke:projects/myproject/locations/us-central1-a/clusters/mylittlecluster \
    --image=my-runsc-installer
```
