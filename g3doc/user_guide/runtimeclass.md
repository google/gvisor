# RuntimeClass

First, follow the appropriate installation instructions for your version of
containerd.

*   For 1.1 or lower, use `gvisor-containerd-shim`.
*   For 1.2 or higher, use `containerd-shim-runsc-v1`.

# Set up the Kubernetes RuntimeClass

Creating the [RuntimeClass][runtimeclass] in Kubernetes is simple once the
runtime is available for containerd:

```shell
cat <<EOF | kubectl apply -f -
apiVersion: node.k8s.io/v1beta1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
EOF
```

Pods can now be created using this RuntimeClass:

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

You can verify that the Pod is running via this RuntimeClass:

```shell
kubectl get pod nginx-gvisor -o wide
```

[runtimeclass]:  https://kubernetes.io/docs/concepts/containers/runtime-class/
