package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "usage_set",
    out = "usage_set.go",
    consts = {
        "minDegree": "10",
    },
    imports = {
        "platform": "gvisor.googlesource.com/gvisor/pkg/sentry/platform",
    },
    package = "filemem",
    prefix = "usage",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "platform.FileRange",
        "Value": "usageInfo",
        "Functions": "usageSetFunctions",
    },
)

go_library(
    name = "filemem",
    srcs = [
        "filemem.go",
        "filemem_state.go",
        "filemem_unsafe.go",
        "usage_set.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/filemem",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/memutil",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
    ],
)

go_test(
    name = "filemem_test",
    size = "small",
    srcs = ["filemem_test.go"],
    embed = [":filemem"],
    deps = ["//pkg/sentry/usermem"],
)
