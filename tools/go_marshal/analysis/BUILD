load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "analysis",
    testonly = 1,
    srcs = ["analysis_unsafe.go"],
    visibility = [
        "//:sandbox",
    ],
)
