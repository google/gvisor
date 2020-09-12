load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "escape",
    testonly = 1,
    srcs = ["escape.go"],
    deps = [
        "//pkg/marshal",
        "//pkg/usermem",
        "//tools/go_marshal/test",
    ],
)
