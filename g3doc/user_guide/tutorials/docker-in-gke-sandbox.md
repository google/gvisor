# Docker in a GKE sandbox

Docker is a platform designed to help developers build, share, and run container
applications.

In gVisor, all basic docker commands should function as expected. The host
network driver and the bridge network driver are tested and supported.

## How to run Docker in a GKE Sandbox

### GKE standard cluster

First, install a GKE standard cluster (1.29.0 or higher) and deploy a node pool
with gVisor enabled. You can view the full documentation
[here](https://cloud.google.com/kubernetes-engine/docs/how-to/sandbox-pods#enabling).

### GKE Autopilot cluster

Alternatively to GKE standard cluster, you could run docker in gVisor at GKE
autopilot cluster, the version needs to be 1.32 or higher. When creating the
autopilot cluster, please add the option `--workload-policies=allow-net-admin`
to allow NET_ADMIN capability that will be granted by the gVisor sandbox.

An example command to start an GKE autopilot cluster will be:

```sh
gcloud container clusters create-auto [CLUTER_NAME] --workload-policies=allow-net-admin --location=[LOCATION] --cluster-version=1.32.2-gke.1182001
```

### Get started

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
  # DNS config is only needed for GKE Autopilot
  dnsPolicy: "None"
  dnsConfig:
    nameservers:
      - "1.1.1.1"
      - "8.8.8.8"
  containers:
  - name: docker-in-gvisor
    image: {registry_url}/docker-in-gvisor:latest
    securityContext:
      capabilities:
        add: [AUDIT_WRITE,CHOWN,DAC_OVERRIDE,FOWNER,FSETID,KILL,MKNOD,NET_BIND_SERVICE,NET_RAW,SETFCAP,SETGID,SETPCAP,SETUID,SYS_CHROOT,SYS_PTRACE,NET_ADMIN,SYS_ADMIN]
    volumeMounts:
      - name: docker
        mountPath: /var/lib/docker
  volumes:
  - name: docker
    emptyDir: {}
```

> gVisor sandbox doesn't need any extra capabilities from the host to run docker
> inside gVisor, the listed capabilities are granted by gVisor to the docker
> daemon that is running inside sandbox.

This YAML file defines a Kubernetes Pod named docker-in-gvisor that will run a
single container from the avagin/docker-in-gvisor:0.1 image.

Apply the pod YAML to your GKE cluster using the kubectl apply command:

```shell
$ kubectl apply -f docker.yaml
```

Verify that the docker-in-gvisor pid is running successfully: `shell $ kubectl
get pods | grep docker-in-gvisor`

#### DNS config

##### GKE standard cluster

The `dnsConfig` in the yaml file is not needed for GKE standard clusters.

##### GKE Autopilot

You have 3 options to deal with DNS config in the cluster:

*   Public DNS

If public DNS works for you, you will be able to leverage public DNS like
`1.1.1.1` or `8.8.8.8` like we listed above;

*   kube-dns

Otherwise, `kube-dns` will be a helpful option. The `kube-dns` is a pod which
deployed with your k8s cluster.

You will look for kube-dns's address you can specify in the `dnsConfig`

```
$ kubectl get services kube-dns -n kube-system
NAME       TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)         AGE
kube-dns   ClusterIP   34.118.224.10   <none>        53/UDP,53/TCP   3d1h
```

*   Host network driver

If you are OK with using Docker host network driver, you can ignore DNS config
in the yaml file. For every command you execute in docker in gVisor, you have to
specify host network driver as `--network=host`.

### Build and run the image with docker in gVisor

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
