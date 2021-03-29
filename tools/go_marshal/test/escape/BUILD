load("//tools:defs.bzl", "go_library")

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
