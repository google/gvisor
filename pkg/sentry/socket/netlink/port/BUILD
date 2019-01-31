package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "port",
    srcs = ["port.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink/port",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "port_test",
    srcs = ["port_test.go"],
    embed = [":port"],
)
