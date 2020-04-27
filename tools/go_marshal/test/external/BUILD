load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "external",
    testonly = 1,
    srcs = ["external.go"],
    marshal = True,
    visibility = ["//tools/go_marshal/test:gomarshal_test"],
)
