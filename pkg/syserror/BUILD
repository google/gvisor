load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "syserror",
    srcs = ["syserror.go"],
    importpath = "gvisor.dev/gvisor/pkg/syserror",
    visibility = ["//visibility:public"],
)

go_test(
    name = "syserror_test",
    srcs = ["syserror_test.go"],
    deps = [
        ":syserror",
    ],
)
