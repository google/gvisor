# Docker in gVisor

Docker is a platform designed to help developers build, share, and run container
applications.

In gVisor, all basic docker commands should function as expected. The host
network driver and the bridge network driver are tested and supported.

### NOTE on runsc setup

To run docker within gvisor, runsc must be enabled to allow raw sockets. This is
not the default, `--net-raw` must be passed to runsc. To use the following
tutorial, that means having the following runtimes configuration in
`/etc/docker/daemon.json`:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--net-raw"
            ]
        }
    }
}
```

If you have an existing entry for `runsc`, likely created by `runsc install`,
then edit the entry and add the `"runtimeArgs"` key and value to the existing
entry.

## How to run Docker in a gVisor container

First, prepare a container image with pre-installed Docker:

```shell
$ docker build -t docker-in-gvisor images/basic/docker
```

In a gVisor sandbox, Docker containers can be started with a set of capabilities
as `audit_write`, `chown`, `dac_override`, `fowner`, `fsetid`, `kill`, `mknod`,
`net_bind_service`, `net_admin`, `net_raw`, `setfcap`, `setgid`, `setpcap`,
`setuid`, `sys_admin`, `sys_chroot`, `sys_ptrace`. For the simplicity, let's
start the sandbox with all capabilities:

```shell
$ docker run --runtime runsc -d --rm --cap-add all --name docker-in-gvisor docker-in-gvisor
```

> gVisor sandbox doesn't need any extra capabilities from the host to run docker
> inside gVisor, the listed capabilities are granted by gVisor to the docker
> daemon that is running inside sandbox.

Now, we can build and run Docker containers.

Let's enter in the gvisor sandbox and run some docker commands:

```shell
docker exec -it docker-in-gvisor bash
```

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

> In the sandbox, we can also run privileged containers by `docker run -it
> --privileged --rm whalesay "Containers do not contain, but gVisor-s do!"`
