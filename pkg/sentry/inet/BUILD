load("//tools:defs.bzl", "go_library")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "inet",
    srcs = [
        "context.go",
        "inet.go",
        "namespace.go",
        "test_stack.go",
    ],
    deps = [
        "//pkg/context",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)
