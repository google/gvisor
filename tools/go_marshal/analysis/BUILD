load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "analysis",
    testonly = 1,
    srcs = ["analysis_unsafe.go"],
    importpath = "gvisor.dev/gvisor/tools/go_marshal/analysis",
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/rand",
    ],
)
