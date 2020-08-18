# Installation

[TOC]

> Note: gVisor supports only x86\_64 and requires Linux 4.14.77+
> ([older Linux](./networking.md#gso)).

## Versions

The `runsc` binaries and repositories are available in multiple versions and
release channels. You should pick the version you'd like to install. For
experimentation, the nightly release is recommended. For production use, the
latest release is recommended.

After selecting an appropriate release channel from the options below, proceed
to the preferred installation mechanism: manual or from an `apt` repository.

### HEAD

Binaries are available for every commit on the `master` branch, and are
available at the following URL:

`https://storage.googleapis.com/gvisor/releases/master/latest/runsc`

Checksums for the release binary are at:

`https://storage.googleapis.com/gvisor/releases/master/latest/runsc.sha512`

For `apt` installation, use the `master` as the `${DIST}` below.

### Nightly

Nightly releases are built most nights from the master branch, and are available
at the following URL:

`https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc`

Checksums for the release binary are at:

`https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc.sha512`

Specific nightly releases can be found at:

`https://storage.googleapis.com/gvisor/releases/nightly/${yyyy-mm-dd}/runsc`

Note that a release may not be available for every day.

For `apt` installation, use the `nightly` as the `${DIST}` below.

### Latest release

The latest official release is available at the following URL:

`https://storage.googleapis.com/gvisor/releases/release/latest`

For `apt` installation, use the `release` as the `${DIST}` below.

### Specific release

A given release release is available at the following URL:

`https://storage.googleapis.com/gvisor/releases/release/${yyyymmdd}`

See the [releases][releases] page for information about specific releases.

For `apt` installation of a specific release, which may include point updates,
use the date of the release, e.g. `${yyyymmdd}`, as the `${DIST}` below.

> Note: only newer releases may be available as `apt` repositories.

### Point release

A given point release is available at the following URL:

`https://storage.googleapis.com/gvisor/releases/release/${yyyymmdd}.${rc}`

Note that `apt` installation of a specific point release is not supported.

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

Next, the key used to sign archives should be added to your `apt` keychain:

```bash
curl -fsSL https://gvisor.dev/archive.key | sudo apt-key add -
```

Based on the release type, you will need to substitute `${DIST}` below, using
one of:

*   `master`: For HEAD.
*   `nightly`: For nightly releases.
*   `release`: For the latest release.
*   `${yyyymmdd}`: For a specific releases (see above).

The repository for the release you wish to install should be added:

```bash
sudo add-apt-repository "deb https://storage.googleapis.com/gvisor/releases ${DIST} main"
```

For example, to install the latest official release, you can use:

```bash
sudo add-apt-repository "deb https://storage.googleapis.com/gvisor/releases release main"
```

Now the runsc package can be installed:

```bash
sudo apt-get update && sudo apt-get install -y runsc
```

If you have Docker installed, it will be automatically configured.

## Install directly

The binary URLs provided above can be used to install directly. For example, the
latest nightly binary can be downloaded, validated, and placed in an appropriate
location by running:

```bash
(
  set -e
  URL=https://storage.googleapis.com/gvisor/releases/nightly/latest
  wget ${URL}/runsc
  wget ${URL}/runsc.sha512
  sha512sum -c runsc.sha512
  rm -f runsc.sha512
  sudo mv runsc /usr/local/bin
  sudo chown root:root /usr/local/bin/runsc
  sudo chmod 0755 /usr/local/bin/runsc
)
```

**It is important to copy this binary to a location that is accessible to all
users, and ensure it is executable by all users**, since `runsc` executes itself
as user `nobody` to avoid unnecessary privileges. The `/usr/local/bin` directory
is a good place to put the `runsc` binary.

After installation, try out `runsc` by following the
[Docker Quick Start](./quick_start/docker.md) or
[OCI Quick Start](./quick_start/oci.md).

[releases]: https://github.com/google/gvisor/releases
