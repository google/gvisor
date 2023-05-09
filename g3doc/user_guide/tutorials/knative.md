# Knative Services

[Knative](https://knative.dev/) is a platform for running serverless workloads
on Kubernetes. This guide will show you how to run basic Knative workloads in
gVisor.

## Prerequisites

This guide assumes you have have a cluster that is capable of running gVisor
workloads. This could be a
[GKE Sandbox](https://cloud.google.com/kubernetes-engine/sandbox/) enabled
cluster on Google Cloud Platform or one you have set up yourself using
[containerd Quick Start](https://gvisor.dev/docs/user_guide/containerd/quick_start/).

This guide will also assume you have Knative installed using
[Istio](https://istio.io/) as the network layer. You can follow the
[Knative installation guide](https://knative.dev/docs/install/install-serving-with-yaml/)
to install Knative.

## Enable the RuntimeClass feature flag

Knative allows the use of various parameters on Pods via
[feature flags](https://knative.dev/docs/serving/feature-flags/). We will enable
the
[runtimeClassName](https://knative.dev/docs/serving/feature-flags/#kubernetes-runtime-class)
feature flag to enable the use of the Kubernetes
[Runtime Class](https://kubernetes.io/docs/concepts/containers/runtime-class/).

Edit the feature flags ConfigMap.

```bash
kubectl edit configmap config-features -n knative-serving
```

Add the `kubernetes.podspec-runtimeclassname: enabled` to the `data` field. Once
you are finished the ConfigMap will look something like this (minus all the
system fields).

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-features
  namespace: knative-serving
  labels:
    serving.knative.dev/release: v0.22.0
data:
  kubernetes.podspec-runtimeclassname: enabled
```

## Deploy the Service

After you have set the Runtime Class feature flag you can now create Knative
services that specify a `runtimeClassName` in the spec.

```bash
cat <<EOF | kubectl apply -f -
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: helloworld-go
spec:
  template:
    spec:
      runtimeClassName: gvisor
      containers:
        - image: gcr.io/knative-samples/helloworld-go
          env:
            - name: TARGET
              value: "gVisor User"
EOF
```

You can see the pods running and their Runtime Class.

```bash
kubectl get pods -o=custom-columns='NAME:.metadata.name,RUNTIME CLASS:.spec.runtimeClassName,STATUS:.status.phase'
```

Output should look something like the following. Note that your service might
scale to zero. If you access it via it's URL you should get a new Pod.

```
NAME                                              RUNTIME CLASS   STATUS
helloworld-go-00002-deployment-646c87b7f5-5v68s   gvisor          Running
```

Congrats! Your Knative service is now running in gVisor!
