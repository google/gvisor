package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "fdnotifier",
    srcs = [
        "fdnotifier.go",
        "poll_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/waiter/fdnotifier",
    visibility = ["//:sandbox"],
    deps = ["//pkg/waiter"],
)
