# gVisor installer image

`//images/gvisor-installer:gvisor_installer` builds the node installer image with
`rules_img`. The payload layer consumes every file in `//:release` and preserves
its layout under `/opt/gvisor/release`. It does not download binaries on nodes.
The separate `nodeinstaller` Go binary is installed at
`/usr/local/bin/nodeinstaller`.

The pinned BusyBox musl base provides a statically linked `nsenter`. Host
containerd and service commands execute in the host mount namespace and root.
The installer image does not need a package manager or a systemd daemon.

Build a Docker-save archive for one architecture:

```sh
mkdir -p /tmp/gvisor-installer-amd64
make copy TARGETS=//images/gvisor-installer:gvisor_installer_archive \
  BAZEL_OPTIONS='--config=x86_64 --compilation_mode=opt' \
  DESTINATION=/tmp/gvisor-installer-amd64/
```

Use `--config=aarch64` for arm64. Release publication combines the two images
into one multiarch reference and stamps the matching chart. Test image cache
tags are not the public release version contract.

## Release publication

`tools/make_kubernetes_release.py` builds from a clean checkout whose exact
version stamp matches the requested release tag. It rejects development and
dirty versions. A tag `release-YYYYMMDD.PATCH` maps to chart version
`YYYYMMDD.PATCH.0`. A date-only tag maps to `YYYYMMDD.0.0`. The chart's
`appVersion` and installer image tag both retain the exact release tag.

Configure both destinations explicitly. No official registry is assumed.
The image repository has no tag or scheme. The chart destination is an OCI
namespace without the chart name or version. These are example destinations:

```sh
export GVISOR_INSTALLER_IMAGE_REPOSITORY=registry.example/project/gvisor-installer
export GVISOR_HELM_REPOSITORY=oci://registry.example/project/charts
python3 tools/make_kubernetes_release.py stage release-20261027.2 \
  /tmp/gvisor-installer-release-20261027.2
```

`stage` requires a new output directory. It builds amd64 and arm64 archives,
packages the chart with the configured image reference, and saves a rendered
`manifest.yaml` and a `release.json` with artifact checksums. It makes no
registry writes. Review these files before running the separate publishing
command:

```sh
python3 tools/make_kubernetes_release.py publish \
  /tmp/gvisor-installer-release-20261027.2
```

`publish` uses the destinations recorded in `release.json` and verifies the
staged checksums. It pushes architecture images with `-amd64` and `-arm64`
suffixes, creates the release-tagged multiarch index from their digests, and
checks the published index before pushing the chart. The resulting references
are `<image-repository>:<release-tag>` and
`<chart-destination>/gvisor:<chart-version>`.

Staging requires Python 3, Git, Make, the configured gVisor build environment,
and Helm with OCI support. Publishing also requires `crane` with its index
commands. Provision Helm and crane credentials for the configured registries
before publishing. The helper does not install tools or authenticate for you.

The release pipeline leaves installer publication disabled by default. Set
`GVISOR_KUBERNETES_RELEASE=true` and configure both destinations to enable it
for `release-*-staging` builds. `ci-stage` runs before Python version injection
changes the checkout. `ci-publish` runs after the existing artifact uploads and
before the final Git release tag is published. Untagged builds skip these
actions. Enabling publication with missing destinations fails the release.
