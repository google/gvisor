package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "limits",
    srcs = [
        "context.go",
        "limits.go",
        "linux.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/limits",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
    ],
)

go_test(
    name = "limits_test",
    size = "small",
    srcs = [
        "limits_test.go",
    ],
    embed = [":limits"],
)
