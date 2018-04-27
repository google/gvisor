package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "usage_state",
    srcs = [
        "cpu.go",
        "io.go",
        "memory.go",
    ],
    out = "usage_state.go",
    package = "usage",
)

go_library(
    name = "usage",
    srcs = [
        "cpu.go",
        "io.go",
        "memory.go",
        "memory_unsafe.go",
        "usage.go",
        "usage_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/usage",
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        "//pkg/bits",
        "//pkg/log",
        "//pkg/sentry/memutil",
        "//pkg/state",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
