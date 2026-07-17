load("//tools:arch.bzl", "select_arch")
load("//tools:defs.bzl", "pkg_deb", "pkg_tar", "version")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

# _SIDECARS maps each sidecar binary target to the filename runsc expects
# to exist under `gvisor-bin/`.
_SIDECARS = {
    "//runsc/checkpointgofer:checkpointgofer_binary": "checkpointgofer",
    "//runsc/cmd/metricserver:runsc-metric-server": "runsc-metric-server",
}

pkg_tar(
    name = "gvisor-bin-tar",
    files = _SIDECARS,
    mode = "0755",
    package_dir = "gvisor-bin",
)
pkg_tar(
    name = "debian-gvisor-bin",
    files = _SIDECARS,
    mode = "0755",
    package_dir = "/usr/bin/gvisor-bin",
)

pkg_tar(
    name = "debian-bin",
    srcs = [
        "//runsc",
        "//shim:containerd-shim-runsc-v1",
    ],
    mode = "0755",
    package_dir = "/usr/bin",
)

pkg_tar(
    name = "debian-data",
    extension = "tar.gz",
    deps = [
        ":debian-bin",
        ":debian-gvisor-bin",
        "//shim:config",
    ],
)

pkg_deb(
    name = "debian",
    architecture = select_arch(
        amd64 = "amd64",
        arm64 = "arm64",
    ),
    conffiles = [
        "/etc/containerd/runsc.toml",
    ],
    data = ":debian-data",
    # Note that the description_file will be flatten (all newlines removed),
    # and therefore it is kept to a simple one-line description. The expected
    # format for debian packages is "short summary\nLonger explanation of
    # tool." and this is impossible with the flattening.
    description_file = "description",
    homepage = "https://gvisor.dev/",
    maintainer = "The gVisor Authors <gvisor-dev@googlegroups.com>",
    package = "runsc",
    package_file_name = "runsc.deb",
    postinst = "postinst.sh",
    version_file = version,
    visibility = [
        "//visibility:public",
    ],
)

# Downloadable release tarball containing all gVisor files.
# This is not the Debian package, but it is in this BUILD file anyway
# because it needs to contain the same set of files in practice, so
# easier to keep in sync.
pkg_tar(
    name = "gvisor-release-tar",
    srcs = [
        "//runsc",
        # containerd shim needs to be at the top level (not gvisor-bin/)
        # because containerd requires it to be in $PATH.
        "//shim:containerd-shim-runsc-v1",
    ],
    deps = [
        # gvisor-bin/ subdir contents:
        ":gvisor-bin-tar"
    ],
    extension = "tar.bz2",
    mode = "0755",
    package_file_name = "gvisor.tar.bz2",
    visibility = ["//visibility:public"],
)
