package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "port_state",
    srcs = ["port.go"],
    out = "port_state.go",
    package = "port",
)

go_library(
    name = "port",
    srcs = [
        "port.go",
        "port_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink/port",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/state"],
)

go_test(
    name = "port_test",
    srcs = ["port_test.go"],
    embed = [":port"],
)
