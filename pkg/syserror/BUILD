package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "syserror",
    srcs = ["syserror.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/syserror",
    visibility = ["//visibility:public"],
)

go_test(
    name = "syserror_test",
    srcs = ["syserror_test.go"],
    deps = [
        ":syserror",
    ],
)
