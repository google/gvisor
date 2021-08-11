load("//tools:defs.bzl", "pkg_deb", "pkg_tar", "select_arch", "version")

package(licenses = ["notice"])

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
        "//shim:config",
    ],
)

pkg_deb(
    name = "debian",
    out = "runsc-latest.deb",
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
