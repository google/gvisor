load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "primitive",
    srcs = [
        "primitive.go",
    ],
    marshal = True,
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/hostarch",
        "//pkg/marshal",
    ],
)
