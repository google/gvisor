load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "coverage",
    srcs = ["coverage.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sync",
        "//pkg/usermem",
        "@io_bazel_rules_go//go/tools/coverdata",
    ],
)
