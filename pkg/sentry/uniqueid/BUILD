package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "uniqueid",
    srcs = ["context.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/uniqueid",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/tcpip/transport/unix",
    ],
)
