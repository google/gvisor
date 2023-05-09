load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "marshal",
    srcs = [
        "marshal.go",
        "util.go",
    ],
    visibility = [
        "//:sandbox",
    ],
    deps = ["//pkg/hostarch"],
)
