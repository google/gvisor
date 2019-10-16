load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "port",
    srcs = ["port.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/socket/netlink/port",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "port_test",
    srcs = ["port_test.go"],
    embed = [":port"],
)
