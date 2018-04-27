package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "fsutil_state",
    srcs = [
        "dirty_set_impl.go",
        "file.go",
        "file_range_set_impl.go",
        "frame_ref_set_impl.go",
        "handle.go",
        "host_file_mapper.go",
        "host_file_mapper_state.go",
        "inode.go",
        "inode_cached.go",
    ],
    out = "fsutil_state.go",
    package = "fsutil",
)

go_template_instance(
    name = "dirty_set_impl",
    out = "dirty_set_impl.go",
    imports = {
        "memmap": "gvisor.googlesource.com/gvisor/pkg/sentry/memmap",
        "platform": "gvisor.googlesource.com/gvisor/pkg/sentry/platform",
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
        "platform": "gvisor.googlesource.com/gvisor/pkg/sentry/platform",
    },
    package = "fsutil",
    prefix = "frameRef",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "platform.FileRange",
        "Value": "uint64",
        "Functions": "frameRefSetFunctions",
    },
)

go_template_instance(
    name = "file_range_set_impl",
    out = "file_range_set_impl.go",
    imports = {
        "memmap": "gvisor.googlesource.com/gvisor/pkg/sentry/memmap",
        "platform": "gvisor.googlesource.com/gvisor/pkg/sentry/platform",
    },
    package = "fsutil",
    prefix = "FileRange",
    template = "//pkg/segment:generic_set",
    types = {
        "Key": "uint64",
        "Range": "memmap.MappableRange",
        "Value": "uint64",
        "Functions": "fileRangeSetFunctions",
    },
)

go_library(
    name = "fsutil",
    srcs = [
        "dirty_set.go",
        "dirty_set_impl.go",
        "file.go",
        "file_range_set.go",
        "file_range_set_impl.go",
        "frame_ref_set.go",
        "frame_ref_set_impl.go",
        "fsutil.go",
        "fsutil_state.go",
        "handle.go",
        "host_file_mapper.go",
        "host_file_mapper_state.go",
        "host_file_mapper_unsafe.go",
        "inode.go",
        "inode_cached.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/fsutil",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/tcpip/transport/unix",
        "//pkg/waiter",
    ],
)

go_test(
    name = "fsutil_x_test",
    size = "small",
    srcs = ["handle_test.go"],
    deps = [
        ":fsutil",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/ramfs/test",
        "//pkg/sentry/usermem",
    ],
)

go_test(
    name = "fsutil_test",
    size = "small",
    srcs = [
        "dirty_set_test.go",
        "inode_cached_test.go",
    ],
    embed = [":fsutil"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usermem",
    ],
)
