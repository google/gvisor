package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

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
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/platform",
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
        "//pkg/syserror",
    ],
)
