load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

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
        "trackGaps": "1",
    },
    imports = {
        "platform": "gvisor.dev/gvisor/pkg/sentry/platform",
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

go_template_instance(
    name = "reclaim_set",
    out = "reclaim_set.go",
    consts = {
        "minDegree": "10",
    },
    imports = {
        "platform": "gvisor.dev/gvisor/pkg/sentry/platform",
    },
    package = "pgalloc",
    prefix = "reclaim",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "platform.FileRange",
        "Value": "reclaimSetValue",
        "Functions": "reclaimSetFunctions",
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
        "reclaim_set.go",
        "save_restore.go",
        "usage_set.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/state",
        "//pkg/state/wire",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

go_test(
    name = "pgalloc_test",
    size = "small",
    srcs = ["pgalloc_test.go"],
    library = ":pgalloc",
    deps = ["//pkg/usermem"],
)
