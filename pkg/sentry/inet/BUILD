load("//tools/go_stateify:defs.bzl", "go_library")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "inet",
    srcs = [
        "context.go",
        "inet.go",
        "test_stack.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/inet",
    deps = [
        "//pkg/sentry/context",
        "//pkg/tcpip",
    ],
)
