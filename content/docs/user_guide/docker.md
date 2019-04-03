+++
title = "Docker Quick Start"
weight = 10
+++
This guide will help you quickly get started running Docker containers using
gVisor.

## Install gVisor

{{% readfile file="docs/includes/install_gvisor.md" markdown="true" %}}

## Configuring Docker

> Note: This guide requires Docker version 17.09.0 or greater. Refer to the
> [Docker documentation][docker] for how to install it.

First you will need to configure Docker to use `runsc` by adding a runtime
entry to your Docker configuration (`/etc/docker/daemon.json`). You may have to
create this file if it does not exist. Also, some Docker versions also require
you to [specify the `storage-driver` field][storage-driver].

In the end, the file should look something like:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc"
        }
    }
}
```

You must restart the Docker daemon after making changes to this file, typically
this is done via `systemd`:

```bash
sudo systemctl restart docker
```

## Running a container

Now run your container using the `runsc` runtime:

```bash
docker run --runtime=runsc --rm hello-world
```

You can also run a terminal to explore the container.

```bash
docker run --runtime=runsc --rm -it ubuntu /bin/bash
```

Many docker options are compatible with gVisor, try them out. Here is an example:

```bash
docker run --runtime=runsc --rm --link backend:database -v ~/bin:/tools:ro -p 8080:80 --cpus=0.5 -it busybox telnet towel.blinkenlights.nl
```

## Verify the runtime

You can verify that you are running in gVisor using the `dmesg` command.

```text
$ docker run --runtime=runsc -it ubuntu dmesg
[    0.000000] Starting gVisor...
[    0.354495] Daemonizing children...
[    0.564053] Constructing home...
[    0.976710] Preparing for the zombie uprising...
[    1.299083] Creating process schedule...
[    1.479987] Committing treasure map to memory...
[    1.704109] Searching for socket adapter...
[    1.748935] Generating random numbers by fair dice roll...
[    2.059747] Digging up root...
[    2.259327] Checking naughty and nice process list...
[    2.610538] Rewriting operating system in Javascript...
[    2.613217] Ready!
```

Note that this is easily replicated by an attacker so applications should never
use `dmesg` to verify the runtime in a security sensitive context.

Next, look at the different options available for gVisor: [platform](../platforms/),
[network](../networking/), [filesystem](../filesystem/).

[docker]: https://docs.docker.com/install/
[storage-driver]: https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-storage-driver
