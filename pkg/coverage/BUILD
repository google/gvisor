load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "coverage",
    srcs = [
        "coverage.go",
        "coverage_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/sync",
        "@io_bazel_rules_go//go/tools/coverdata",
    ],
)
