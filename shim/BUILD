load("//tools:defs.bzl", "go_binary", "pkg_tar")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "go_export_sources",
    srcs = glob(
        ["*.go"],
        exclude = ["*_test.go"],
    ),
    visibility = ["//:__pkg__"],
)

go_binary(
    name = "containerd-shim-runsc-v1",
    srcs = ["main.go"],
    features = ["fully_static_link"],
    tags = ["staging"],
    visibility = [
        "//visibility:public",
    ],
    deps = ["//shim/v1/cli"],
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
