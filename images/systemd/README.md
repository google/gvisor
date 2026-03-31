# Systemd Test Image

This directory contains a Dockerfile for building a `systemd` test image. This
image is primarily used for testing gVisor's compatibility with `systemd` and
its various components.

## Prerequisites

Before running the tests, ensure you have gVisor built and configured as a
Docker runtime.

```bash
# Build gVisor and install the dev runtime (runsc-d)
make dev
```

## Building the Image

To build the `systemd` test image, run:

```bash
docker build //images/systemd -t systemd-test-image
```

Alternatively, you can use the `make` workflow from the top-level directory:

```bash
make load-systemd
```

## Running the Tests

To run the `systemd` tests within the container using gVisor, execute:

```bash
docker run --runtime=sandbox-cgroup-d --privileged \
  -v /tmp/systemd:/systemd/build/meson-logs -it systemd-tests \
  meson test -C build/ --print-errorlogs
```

> [!IMPORTANT] The `--privileged` flag is required because `systemd` tests often
> need to perform operations that are restricted in a standard container
> environment, such as mounting filesystems or interacting with device nodes.

## Implementation Details

The [Dockerfile](./Dockerfile) performs the following steps: 1. Starts from a
recent Ubuntu base image. 2. Installs necessary build dependencies (`meson`,
`ninja`, `gcc`, etc.). 3. Clones the `systemd` repository from GitHub. 4.
Configures the build using `meson`, disabling heavy optional features (like man
pages and HTML documentation) to speed up the build and test cycle. 5. Compiles
`systemd` using `ninja`.
