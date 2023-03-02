load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "escape",
    testonly = 1,
    srcs = ["escape.go"],
    deps = [
        "//pkg/hostarch",
        "//pkg/marshal",
        "//tools/go_marshal/test",
    ],
)
