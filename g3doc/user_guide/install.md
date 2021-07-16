# Installation

[TOC]

> Note: gVisor supports only x86\_64 and requires Linux 4.14.77+
> ([older Linux](./networking.md#gso)).

## Install latest release {#install-latest}

To download and install the latest release manually follow these steps:

```bash
(
  set -e
  ARCH=$(uname -m)
  URL=https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}
  wget ${URL}/runsc ${URL}/runsc.sha512 \
    ${URL}/containerd-shim-runsc-v1 ${URL}/containerd-shim-runsc-v1.sha512
  sha512sum -c runsc.sha512 \
    -c containerd-shim-runsc-v1.sha512
  rm -f *.sha512
  chmod a+rx runsc containerd-shim-runsc-v1
  sudo mv runsc containerd-shim-runsc-v1 /usr/local/bin
)
```

To install gVisor as a Docker runtime, run the following commands:

```bash
/usr/local/bin/runsc install
sudo systemctl reload docker
docker run --rm --runtime=runsc hello-world
```

For more details about using gVisor with Docker, see
[Docker Quick Start](./quick_start/docker.md)

Note: It is important to copy `runsc` to a location that is readable and
executable to all users, since `runsc` executes itself as user `nobody` to avoid
unnecessary privileges. The `/usr/local/bin` directory is a good place to put
the `runsc` binary.

## Install from an `apt` repository

First, appropriate dependencies must be installed to allow `apt` to install
packages via https:

```bash
sudo apt-get update && \
sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common
```

Next, configure the key used to sign archives and the repository.

NOTE: The key was updated on 2021-07-13 to replace the expired key. If you get
errors about the key being expired, run the `apt-key add` command below again.

```bash
curl -fsSL https://gvisor.dev/archive.key | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64,arm64] https://storage.googleapis.com/gvisor/releases release main"
```

Now the runsc package can be installed:

```bash
sudo apt-get update && sudo apt-get install -y runsc
```

If you have Docker installed, it will be automatically configured.

## Versions

The `runsc` binaries and repositories are available in multiple versions and
release channels. You should pick the version you'd like to install. For
experimentation, the nightly release is recommended. For production use, the
latest release is recommended.

After selecting an appropriate release channel from the options below, proceed
to the preferred installation mechanism: manual or from an `apt` repository.

> Note: Older releases are still available but may not have an `${ARCH}`
> component in the URL. These release were available for `x86_64` only.

### HEAD

Binaries are available for every commit on the `master` branch, and are
available at the following URL:

`https://storage.googleapis.com/gvisor/releases/master/latest/${ARCH}`

You can use this link with the steps described in
[Install latest release](#install-latest).

For `apt` installation, use the `master` to configure the repository:

```bash
sudo add-apt-repository "deb [arch=amd64,arm64] https://storage.googleapis.com/gvisor/releases master main"
```

### Nightly

Nightly releases are built most nights from the master branch, and are available
at the following URL:

`https://storage.googleapis.com/gvisor/releases/nightly/latest/${ARCH}`

You can use this link with the steps described in
[Install latest release](#install-latest).

Specific nightly releases can be found at:

`https://storage.googleapis.com/gvisor/releases/nightly/${yyyy-mm-dd}/${ARCH}`

Note that a release may not be available for every day.

For `apt` installation, use the `nightly` to configure the repository:

```bash
sudo add-apt-repository "deb [arch=amd64,arm64] https://storage.googleapis.com/gvisor/releases nightly main"
```

### Latest release

The latest official release is available at the following URL:

`https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}`

You can use this link with the steps described in
[Install latest release](#install-latest).

For `apt` installation, use the `release` to configure the repository:

```bash
sudo add-apt-repository "deb [arch=amd64,arm64] https://storage.googleapis.com/gvisor/releases release main"
```

### Specific release

Specific releases are the latest [point release](#point-release) for a given
date. Specific releases should be available for any date that has a point
release. A given release is available at the following URL:

`https://storage.googleapis.com/gvisor/releases/release/${yyyymmdd}/${ARCH}`

You can use this link with the steps described in
[Install latest release](#install-latest).

See the [releases](https://github.com/google/gvisor/releases) page for
information about specific releases.

For `apt` installation of a specific release, which may include point updates,
use the date of the release for repository, e.g. `${yyyymmdd}`.

```bash
sudo add-apt-repository "deb [arch=amd64,arm64] https://storage.googleapis.com/gvisor/releases yyyymmdd main"
```

> Note: only newer releases may be available as `apt` repositories.

### Point release

Point releases correspond to
[releases](https://github.com/google/gvisor/releases) tagged in the Github
repository. A given point release is available at the following URL:

`https://storage.googleapis.com/gvisor/releases/release/${yyyymmdd}.${rc}/${ARCH}`

You can use this link with the steps described in
[Install latest release](#install-latest).

Note that `apt` installation of a specific point release is not supported.

After installation, try out `runsc` by following the
[Docker Quick Start](./quick_start/docker.md),
[Containerd QuickStart](./containerd/quick_start.md), or
[OCI Quick Start](./quick_start/oci.md).
