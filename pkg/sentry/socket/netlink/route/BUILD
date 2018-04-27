package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "route_state",
    srcs = ["protocol.go"],
    out = "route_state.go",
    package = "route",
)

go_library(
    name = "route",
    srcs = [
        "protocol.go",
        "route_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink/route",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket/netlink",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserr",
    ],
)
