+++
title = "OCI"
weight = 30
+++

This guide will quickly get you started running your first gVisor sandbox
container using the runtime directly with the default platform.

## Install gVisor

First, install gVisor using the [install instructions][install].

## Run an OCI compatible container

Now we will create an [OCI][oci] container bundle to run our container. First we
will create a root directory for our bundle.

```bash
mkdir bundle
cd bundle
```

Create a root file system for the container. We will use the Docker hello-world
image as the basis for our container.

```bash
mkdir rootfs
docker export $(docker create hello-world) | tar -xf - -C rootfs
```

Next, create an specification file called `config.json` that contains our
container specification. We will update the default command it runs to `/hello`
in the `hello-world` container.

```bash
runsc spec
sed -i 's;"sh";"/hello";' config.json
```

Finally run the container.

```bash
sudo runsc run hello
```

Next try [running gVisor using Docker](../docker/).

[oci]: https://opencontainers.org/

[install]: /docs/user_guide/install
