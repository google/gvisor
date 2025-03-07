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

Follow the
[Knative installation guide](https://knative.dev/docs/install/install-serving-with-yaml/)
to install Knative.

## Enable the RuntimeClassName deployment config

Knative allows the use of various parameters on Pods via
[deployment configs](https://knative.dev/docs/serving/configuration/deployment)
amongst other things. We will set the
[runtime-class-name](https://knative.dev/docs/serving/configuration/deployment/#configuring-selectable-runtimeclassname)
property to configure the Kubernetes deployments created by Knative.

Edit the deployment ConfigMap.

```bash
kubectl edit configmap config-deployment -n knative-serving
```

Setting the `runtime-class-name` configures the Pod field by label selectors.

Enforce all Pods run through Knative to use gVisor as the Runtime Class:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-deployment
  namespace: knative-serving
data:
  runtime-class-name: |
    gvisor: {}
```

Allow exception for Pods to run without gVisor as the Runtime Class when a label
is set:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-deployment
  namespace: knative-serving
data:
  runtime-class-name: |
    "":
      selector:
        no-isolation-here: "true"
    gvisor: {}
```

## Deploy the Service

After you have set the Runtime Class deployment config you can now create
Knative Service.

```bash
cat <<EOF | kubectl apply -f -
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: helloworld-go
spec:
  template:
    spec:
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
