# Docker in gVisor

Docker is a platform designed to help developers build, share, and run container
applications.

In gVisor, all basic docker commands should function as expected. However, it's
important to note that, currently, only the host network driver is supported.
This means that both 'docker run' and 'docker build' commands must be executed
with the `--network=host` option.

## How to run Docker in a gVisor container

First, prepare a container image with pre-installed Docker:

```shell
$ cd images/basic/docker/
$ docker build -t docker-in-gvisor .
```

Since Docker requires root privileges and a full set of capabilities, a gVisor
sandbox needs to be started in privileged mode:

```shell
$ docker run --runtime runsc -it --rm --privileged docker-in-gvisor bash
```

All following commands have to be executed inside a gVsior sandbox.

For the Docker daemon to operate correctly, the devices cgroup must be mounted
using the following commands:

```shell
mount -t tmpfs cgroups /sys/fs/cgroup
mkdir /sys/fs/cgroup/devices
mount -t cgroup -o devices devices /sys/fs/cgroup/devices
```

Afterwards, the daemon can be started with the following command:

```shell
/usr/bin/dockerd --bridge=none --iptables=false --ip6tables=false
```

Now, we can build and run Docker containers

```shell
$ mkdir whalesay && cd whalesay
$ cat > Dockerfile <<EOF
FROM ubuntu

RUN apt-get update && apt-get install -y cowsay curl
RUN mkdir -p /usr/share/cowsay/cows/
RUN curl -o /usr/share/cowsay/cows/docker.cow https://raw.githubusercontent.com/docker/whalesay/master/docker.cow
ENTRYPOINT ["/usr/games/cowsay", "-f", "docker.cow"]
EOF
$ docker build --network=host -t whalesay .
....
Successfully tagged whalesay:latest
$ docker run --network host -it --rm whalesay "Containers do not contain, but gVisor-s do!"
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
