load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "cgoextras",
    srcs = [
        "cgoextras.go",
        "pacdisable_cgo_arm64.go",
    ],
    bazel_cgo = True,
    visibility = [
        "//:__pkg__",
        "//runsc:__subpackages__",
    ],
)
