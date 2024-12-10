# Docker in a GKE sandbox

Docker is a platform designed to help developers build, share, and run container
applications.

In gVisor, all basic docker commands should function as expected. The host
network driver and the bridge network driver are tested and supported.

## How to run Docker in a GKE Sandbox

First, install a GKE cluster (1.29.0 or higher) and deploy a node pool with
gVisor enabled. You can view the full documentation
[here](https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods#enabling).

Prepare a container image with pre-installed Docker:

```shell
$ docker build -t docker-in-gvisor images/basic/docker
$ docker push {registry_url}/docker-in-gvisor:latest
```

Create a Kubernetes pod YAML file (docker.yaml) with the following content:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: docker-in-gvisor
spec:
  runtimeClassName: gvisor
  containers:
  - name: docker-in-gvisor
    image: {registry_url}/docker-in-gvisor:latest
    securityContext:
      capabilities:
        add: ["all"]
    volumeMounts:
      - name: docker
        mountPath: /var/lib/docker
  volumes:
  - name: docker
    emptyDir: {}
```

This YAML file defines a Kubernetes Pod named docker-in-gvisor that will run a
single container from the avagin/docker-in-gvisor:0.1 image.

Apply the pod YAML to your GKE cluster using the kubectl apply command:

```shell
$ kubectl apply -f docker.yaml
```

Verify that the docker-in-gvisor pid is running successfully: `shell $ kubectl
get pods | grep docker-in-gvisor`

You can access the container by executing a shell inside it. Use the following
command:

```shell
kubectl exec -it docker-in-gvisor -- bash
```

Now, we can build and run Docker containers.

```shell
$ mkdir whalesay && cd whalesay
$ cat > Dockerfile <<EOF
FROM ubuntu

RUN apt-get update && apt-get install -y cowsay curl
RUN mkdir -p /usr/share/cowsay/cows/
RUN curl -o /usr/share/cowsay/cows/docker.cow https://raw.githubusercontent.com/docker/whalesay/master/docker.cow
ENTRYPOINT ["/usr/games/cowsay", "-f", "docker.cow"]
EOF
$ docker build -t whalesay .
....
Successfully tagged whalesay:latest
$ docker run -it --rm whalesay "Containers do not contain, but gVisor-s do!"
 _________________________________________
/ Containers do not contain, but gVisor-s \
\ do!                                     /
 -----------------------------------------
   \               ##         .
    \        ## ## ##        ==
          ## ## ## ##       ===
       /""""""""""""""""\___/ ===
  ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ /  ===- ~~~
       \______ o          __/
         \    \        __/
          \____\______/

```
