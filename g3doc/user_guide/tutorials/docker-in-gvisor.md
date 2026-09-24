# Docker in gVisor

Docker is a platform designed to help developers build, share, and run container
applications.

In gVisor, all basic docker commands should function as expected. The host
network driver and the bridge network driver are tested and supported.

### Supported Docker Versions

<!-- mdformat off -->

| Docker Version | Support Status | Required gVisor Configuration |
| -------------- | -------------- | ----------------------------- |
| Docker v27     | Supported      | * `--net-raw` |
| Docker v28     | Supported      | * `--net-raw`<br>* `--allow-packet-socket-write` |
| Docker v29     | Supported      | * `--net-raw`<br>* `--allow-packet-socket-write`<br>* Either `tmpfs` mount at `/var/lib/docker` OR `--feature containerd-snapshotter=false` |

<!-- mdformat on -->

### Limitations

-   `dockerd` inside gVisor needs to be executed with flags `--iptables=false
    --ip6tables=false` and additional network setup is needed, check
    [images/basic/docker/start-dockerd.sh](https://github.com/google/gvisor/blob/master/images/basic/docker/start-dockerd.sh)
    for reference. With iptables disabled, `docker run --expose=` does not
    expose the port; if a nested container needs to expose ports, inside gVisor
    use `docker run --network=host`.

### Configuration Reference

To run Docker inside gVisor, you need to configure `runsc` and potentially the
container storage depending on the Docker version.

#### runsc Flags (in `/etc/docker/daemon.json`)

To update your `/etc/docker/daemon.json` with the necessary `runtimeArgs`:

*   **`--net-raw`** (Required for all Docker versions)
    *   Enables raw sockets inside the sandbox. This is required for Docker's
        networking to function.
*   **`--allow-packet-socket-write`** (Required for Docker v28 and later)
    *   Allows the sandbox to write to `AF_PACKET` sockets. This is necessary
        because `dockerd` (v28+) sends unsolicited ARP/NA requests when bringing
        up network interfaces.
    *   > **Note:** `--allow-packet-socket-write` allows sandboxed code to craft
        arbitrary network packets.

##### Example `/etc/docker/daemon.json`

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--net-raw",
                "--allow-packet-socket-write"
            ]
        }
    }
}
```

If you have an existing entry for `runsc` (likely created by `runsc install`),
edit the entry to add the `"runtimeArgs"` key and value.

#### Docker Storage Backend

Since version 29, Docker Engine defaults to using the containerd image store,
which uses `overlayfs` for container root filesystems.

In nested container and sandbox environments where `/var/lib/docker` is already
on an `overlayfs` mount, attempting to mount another `overlayfs` on top will
fail because Linux does not permit overlay-on-overlay mounts (and gVisor
currently requires `tmpfs` as an upper layer for `overlayfs`).

To run Docker in gVisor, you must use one of the following workarounds:

*   **Mount `tmpfs` at `/var/lib/docker` (Recommended):** Mount a `tmpfs`
    filesystem at `/var/lib/docker` before starting the Docker daemon inside the
    sandbox so `overlayfs` can use `tmpfs` as its backing store.
*   **Disable containerd image store:** Launch `dockerd` with `--feature
    containerd-snapshotter=false` to fall back to classic storage drivers.

See
[images/basic/docker/start-dockerd.sh](https://github.com/google/gvisor/blob/master/images/basic/docker/start-dockerd.sh)
as a reference implementation of how to handle these configurations at container
startup.

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
# NOTE: `--cap-add` does *NOT* grant any host capabilities. See below.
$ docker run --runtime runsc -d --rm --cap-add all --name docker-in-gvisor docker-in-gvisor
```

> **NOTE**: **gVisor *never* runs with capabilities** on the host Linux kernel,
> even when the above `--cap-add all` flag. This flag only controls the
> capabilities *perceived* by the in-sandbox application (in this case, the
> in-sandbox Docker daemon). This does not provide the sandboxed application,
> nor the gVisor sandbox itself, any host privileges.

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
