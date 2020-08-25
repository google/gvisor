load("//tools:defs.bzl", "pkg_deb", "pkg_tar")

package(licenses = ["notice"])

pkg_tar(
    name = "debian-bin",
    srcs = [
        "//runsc",
        "//shim/v1:gvisor-containerd-shim",
        "//shim/v2:containerd-shim-runsc-v1",
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

genrule(
    name = "debian-version",
    # Note that runsc must appear in the srcs parameter and not the tools
    # parameter, otherwise it will not be stamped. This is reasonable, as tools
    # may be encoded differently in the build graph (cached more aggressively
    # because they are assumes to be hermetic).
    srcs = ["//runsc"],
    outs = ["version.txt"],
    # Note that the little dance here is necessary because files in the $(SRCS)
    # attribute are not executable by default, and we can't touch in place.
    cmd = "cp $(location //runsc:runsc) $(@D)/runsc && \
        chmod a+x $(@D)/runsc && \
        $(@D)/runsc -version | grep version | sed 's/^[^0-9]*//' > $@ && \
        rm -f $(@D)/runsc",
    stamp = 1,
)

pkg_deb(
    name = "debian",
    architecture = "amd64",
    data = ":debian-data",
    # Note that the description_file will be flatten (all newlines removed),
    # and therefore it is kept to a simple one-line description. The expected
    # format for debian packages is "short summary\nLonger explanation of
    # tool." and this is impossible with the flattening.
    description_file = "description",
    homepage = "https://gvisor.dev/",
    maintainer = "The gVisor Authors <gvisor-dev@googlegroups.com>",
    package = "runsc",
    postinst = "postinst.sh",
    version_file = ":version.txt",
    visibility = [
        "//visibility:public",
    ],
)
