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
$ docker run --runtime runsc -d --rm --privileged --name docker-in-gvisor docker-in-gvisor
```

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
