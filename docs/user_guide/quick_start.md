# Quick Start

This guide will quickly get you started running your first gVisor sandbox
container.

Some requirements:

-   gVisor requires Linux x86\_64 Linux 3.17+
-   This guide requires Docker. Read the Docker documentation for how to install
    it on how to [install Docker](https://docs.docker.com/install/)

## Install gVisor

The easiest way to get `runsc` is from the
[latest nightly build][runsc-nightly]. After you download the binary, check it
against the SHA512 [checksum file][runsc-nightly-sha]. Older builds can be found
here:
`https://storage.googleapis.com/gvisor/releases/nightly/${yyyy-mm-dd}/runsc` and
`https://storage.googleapis.com/gvisor/releases/nightly/${yyyy-mm-dd}/runsc.sha512`

**It is important to copy this binary to some place that is accessible to all
users, and make is executable to all users**, since `runsc` executes itself as
user `nobody` to avoid unnecessary privileges. The `/usr/local/bin` directory is
a good place to put the `runsc` binary.

```
wget https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc
wget https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc.sha512
sha512sum -c runsc.sha512
chmod a+x runsc
sudo mv runsc /usr/local/bin
```

## Run an OCI compatible container

Now we will create an [OCI][oci] container bundle to run our container. First we
will create a root directory for our bundle.

```
$ mkdir bundle
$ cd bundle
```

Create a root file system for the container. We will use the Docker hello-world
image as the basis for our container.

```
$ mkdir rootfs
$ docker export $(docker create hello-world) | tar -xf - -C rootfs
```

Next, create an specification file called `config.json` that contains our
container specification. We will update the default command it runs to `/hello`
in the `hello-world` container.

```
$ runsc spec
$ sed -i 's;"sh";"/hello";' config.json
```

Finally run the container.

```
$ sudo runsc run hello
```

\[TODO]:# Add some next steps

[runsc-nightly-sha]: https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc.sha512
[runsc-nightly]: https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc
[oci]: https://www.opencontainers.org
