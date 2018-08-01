package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "waiter",
    srcs = ["waiter.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/waiter",
    visibility = ["//visibility:public"],
    deps = ["//pkg/ilist"],
)

go_test(
    name = "waiter_test",
    size = "small",
    srcs = [
        "waiter_test.go",
    ],
    embed = [":waiter"],
)
