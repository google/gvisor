load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "uds",
    testonly = 1,
    srcs = ["uds.go"],
    importpath = "gvisor.dev/gvisor/test/uds",
    deps = [
        "//pkg/log",
        "//pkg/unet",
    ],
)
