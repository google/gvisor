# OCI Quick Start

This guide will quickly get you started running your first gVisor sandbox
container using the runtime directly with the default platform.

First, follow the [Installation guide][install].

## Run an OCI compatible container

Now we will create an [OCI][oci] container bundle to run our container. First we
will create a root directory for our bundle.

```bash
mkdir bundle
cd bundle
```

Create a root file system for the container. We will use the Docker
`hello-world` image as the basis for our container.

```bash
mkdir --mode=0755 rootfs
docker export $(docker create hello-world) | sudo tar -xf - -C rootfs --same-owner --same-permissions
```

Next, create an specification file called `config.json` that contains our
container specification. We tell the container to run the `/hello` program.

```bash
runsc spec -- /hello
```

Finally run the container.

```bash
sudo runsc run hello
```

Next try [using CNI to set up networking](../../../tutorials/cni/) or
[running gVisor using Docker](../docker/).

[oci]: https://opencontainers.org/
[install]: /docs/user_guide/install
