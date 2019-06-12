package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "evictable_range",
    out = "evictable_range.go",
    package = "pgalloc",
    prefix = "Evictable",
    template = "//pkg/segment:generic_range",
    types = {
        "T": "uint64",
    },
)

go_template_instance(
    name = "evictable_range_set",
    out = "evictable_range_set.go",
    package = "pgalloc",
    prefix = "evictableRange",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "EvictableRange",
        "Value": "evictableRangeSetValue",
        "Functions": "evictableRangeSetFunctions",
    },
)

go_template_instance(
    name = "usage_set",
    out = "usage_set.go",
    consts = {
        "minDegree": "10",
    },
    imports = {
        "platform": "gvisor.googlesource.com/gvisor/pkg/sentry/platform",
    },
    package = "pgalloc",
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
    name = "pgalloc",
    srcs = [
        "context.go",
        "evictable_range.go",
        "evictable_range_set.go",
        "pgalloc.go",
        "pgalloc_unsafe.go",
        "save_restore.go",
        "usage_set.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/pgalloc",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
    ],
)

go_test(
    name = "pgalloc_test",
    size = "small",
    srcs = ["pgalloc_test.go"],
    embed = [":pgalloc"],
    deps = ["//pkg/sentry/usermem"],
)
