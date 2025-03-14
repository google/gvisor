load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "timing",
    srcs = ["timing.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
    ],
)
