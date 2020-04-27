load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "fdchannel",
    srcs = ["fdchannel_unsafe.go"],
    visibility = ["//visibility:public"],
)

go_test(
    name = "fdchannel_test",
    size = "small",
    srcs = ["fdchannel_test.go"],
    library = ":fdchannel",
    deps = ["//pkg/sync"],
)
