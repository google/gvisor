load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "refs_mutex",
    out = "refs_mutex.go",
    package = "fsutil",
    prefix = "refs",
)

declare_mutex(
    name = "maps_mutex",
    out = "maps_mutex.go",
    package = "fsutil",
    prefix = "maps",
)

go_template_instance(
    name = "dirty_set_impl",
    out = "dirty_set_impl.go",
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "fsutil",
    prefix = "Dirty",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.MappableRange",
        "Value": "DirtyInfo",
        "Functions": "dirtySetFunctions",
    },
)

go_template_instance(
    name = "frame_ref_set_impl",
    out = "frame_ref_set_impl.go",
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "fsutil",
    prefix = "FrameRef",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.FileRange",
        "Value": "FrameRefSegInfo",
        "Functions": "FrameRefSetFunctions",
    },
)

go_template_instance(
    name = "file_range_set_impl",
    out = "file_range_set_impl.go",
    imports = {
        "memmap": "gvisor.dev/gvisor/pkg/sentry/memmap",
    },
    package = "fsutil",
    prefix = "FileRange",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.MappableRange",
        "Value": "uint64",
        "Functions": "FileRangeSetFunctions",
    },
)

go_library(
    name = "fsutil",
    srcs = [
        "dirty_set.go",
        "dirty_set_impl.go",
        "file_range_set.go",
        "file_range_set_impl.go",
        "frame_ref_set.go",
        "frame_ref_set_impl.go",
        "fsutil.go",
        "host_file_mapper.go",
        "host_file_mapper_state.go",
        "host_file_mapper_unsafe.go",
        "maps_mutex.go",
        "refs_mutex.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/state",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fsutil_test",
    size = "small",
    srcs = [
        "dirty_set_test.go",
    ],
    library = ":fsutil",
    deps = [
        "//pkg/hostarch",
        "//pkg/sentry/memmap",
    ],
)
