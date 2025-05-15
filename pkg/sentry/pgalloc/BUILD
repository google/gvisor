load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "apl_shared_mutex",
    out = "apl_shared_mutex.go",
    package = "pgalloc",
    prefix = "aplShared",
)

declare_mutex(
    name = "memory_file_mutex",
    out = "memory_file_mutex.go",
    package = "pgalloc",
    prefix = "memoryFile",
)

go_template_instance(
    name = "apl_unloaded_set",
    out = "apl_unloaded_set.go",
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "pgalloc",
    prefix = "aplUnloaded",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.FileRange",
        "Value": "aplUnloadedInfo",
        "Functions": "aplUnloadedSetFunctions",
    },
)

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
    name = "memacct_set",
    out = "memacct_set.go",
    consts = {
        "minDegree": "10",
    },
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "pgalloc",
    prefix = "memAcct",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.FileRange",
        "Value": "memAcctInfo",
        "Functions": "memAcctSetFunctions",
    },
)

go_template_instance(
    name = "unfree_set",
    out = "unfree_set.go",
    consts = {
        "minDegree": "10",
        "trackGaps": "1",
    },
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "pgalloc",
    prefix = "unfree",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.FileRange",
        "Value": "unfreeInfo",
        "Functions": "unfreeSetFunctions",
    },
)

go_template_instance(
    name = "unwaste_set",
    out = "unwaste_set.go",
    consts = {
        "minDegree": "10",
        "trackGaps": "1",
    },
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "pgalloc",
    prefix = "unwaste",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.FileRange",
        "Value": "unwasteInfo",
        "Functions": "unwasteSetFunctions",
    },
)

go_library(
    name = "pgalloc",
    srcs = [
        "apl_shared_mutex.go",
        "apl_unloaded_set.go",
        "context.go",
        "debug.go",
        "evictable_range.go",
        "evictable_range_set.go",
        "memacct_set.go",
        "memory_file_mutex.go",
        "pgalloc.go",
        "pgalloc_unsafe.go",
        "save_restore.go",
        "unfree_set.go",
        "unwaste_set.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/aio",
        "//pkg/atomicbitops",
        "//pkg/bitmap",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/gohacks",
        "//pkg/goid",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/ringdeque",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usage",
        "//pkg/state",
        "//pkg/state/wire",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/syncevent",
        "//pkg/timing",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "pgalloc_test",
    size = "small",
    srcs = ["pgalloc_test.go"],
    library = ":pgalloc",
    deps = [
        "//pkg/hostarch",
        "//pkg/sentry/memmap",
    ],
)
