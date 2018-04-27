package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "platform_state",
    srcs = [
        "file_range.go",
    ],
    out = "platform_state.go",
    package = "platform",
)

go_template_instance(
    name = "file_range",
    out = "file_range.go",
    package = "platform",
    prefix = "File",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_library(
    name = "platform",
    srcs = [
        "context.go",
        "file_range.go",
        "mmap_min_addr.go",
        "platform.go",
        "platform_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/platform/safecopy",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
    ],
)
