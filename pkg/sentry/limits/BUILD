package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "limits_state",
    srcs = [
        "limits.go",
    ],
    out = "limits_state.go",
    package = "limits",
)

go_library(
    name = "limits",
    srcs = [
        "context.go",
        "limits.go",
        "limits_state.go",
        "linux.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/limits",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/state",
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
