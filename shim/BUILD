load("//tools:defs.bzl", "pkg_tar")

package(licenses = ["notice"])

pkg_tar(
    name = "config",
    srcs = [
        "runsc.toml",
    ],
    mode = "0644",
    package_dir = "/etc/containerd",
    visibility = [
        "//runsc:__pkg__",
    ],
)
