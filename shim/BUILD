load("//tools:defs.bzl", "go_binary", "pkg_tar")

package(licenses = ["notice"])

go_binary(
    name = "containerd-shim-runsc-v1",
    srcs = ["main.go"],
    static = True,
    visibility = [
        "//visibility:public",
    ],
    deps = ["//shim/cli"],
)

pkg_tar(
    name = "config",
    srcs = [
        "runsc.toml",
    ],
    mode = "0644",
    package_dir = "/etc/containerd",
    visibility = [
        "//visibility:public",
    ],
)
