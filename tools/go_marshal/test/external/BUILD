load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "external",
    testonly = 1,
    srcs = ["external.go"],
    marshal = True,
    visibility = ["//tools/go_marshal/test:gomarshal_test"],
)
