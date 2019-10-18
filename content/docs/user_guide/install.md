+++
title = "Installation"
weight = 20
+++

> Note: gVisor supports only x86\_64 and requires Linux {{< required_linux >}}
> ([older Linux][old-linux]).

## Versions

The `runsc` binaries and repositories are available in multiple versions and
release channels. You should pick the version you'd like to install. For
experimentation, the nightly release is recommended. For production use, the
latest release is recommended.

After selecting an appropriate release channel from the options below, proceed
to the preferred installation mechanism: manual or from an `apt` repository.

### Nightly

Nightly releases are built most nights from the master branch, and are available
at the following URL:

   `https://storage.googleapis.com/gvisor/releases/nightly/latest`

Specific nightly releases can be found at:

   `https://storage.googleapis.com/gvisor/releases/nightly/${yyyy-mm-dd}`

Note that a release may not be available for every day.

To use a nightly release, use one of the above URLs for `URL` in the manual
instructions below. For `apt`, use `nightly` for `DIST` below.

### Latest release

The latest official release is available at the following URL:

   `https://storage.googleapis.com/gvisor/releases/release/latest`

To use the latest release, use the above URL for `URL` in the manual
instructions below. For `apt`, use `latest` for `DIST` below.

### Specific release

A given release release is available at the following URL:

  `https://storage.googleapis.com/gvisor/releases/release/${yyyymmdd}`

See the [releases][releases] page for information about specific releases.

This will include point updates for the release, if required. To use a specific
release, use the above URL for `URL` in the manual instructions below. For
`apt`, use `${yyyymmdd}` for `DIST` below.

### Point release

A given point release is available at the following URL:

  `https://storage.googleapis.com/gvisor/releases/release/${yyyymmdd}.${rc}`

Unlike the specific release above, which may include updates, this release will
not change. To use a specific point release, use the above URL for `URL` in the
manual instructions below. For apt, use `${yyyymmdd}.${rc}` for `DIST` below.

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

 * `nightly`: For all nightly releases.
 * `latest`: For the latest release.
 * `${yyyymmdd}`: For specific releases.
 * `${yyyymmdd}.${rc}`: For a specific point release.

The repository for the release you wish to install should be added:

```bash
sudo add-apt-repository \
   "deb https://storage.googleapis.com/gvisor/releases" \
   "${DIST}" \
   main
```

For example, to install the latest official release, you can use:

```bash
sudo add-apt-repository \
   "deb https://storage.googleapis.com/gvisor/releases" \
   latest \
   main
```

Now the runsc package can be installed:

```bash
sudo apt-get update && sudo apt-get install -y runsc
```

If you have Docker installed, it will be automatically configured.

## Install manually

After selecting an appropriate `URL` above, you can download `runsc` directly
from `${URL}/runsc` ([latest][latest-nightly]) and a checksum hash from
`${URL}/runsc.sha512` ([latest][latest-hash]).

For example, this binary can be downloaded, validated, and placed in an
appropriate location by running:

```bash
(
  set -e
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

After installation, the`runsc` binary comes with an `install` command that can
optionally automatically configure Docker:

```bash
runsc install
```

[latest-nightly]: https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc

[latest-hash]: https://storage.googleapis.com/gvisor/releases/nightly/latest/runsc.sha512

[oci]: https://www.opencontainers.org

[old-linux]: /docs/user_guide/networking/#gso

[releases]: https://github.com/google/gvisor/releases
