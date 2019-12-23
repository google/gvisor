load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "slot_list",
    out = "slot_list.go",
    package = "kernfs",
    prefix = "slot",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*slot",
        "Linker": "*slot",
    },
)

go_library(
    name = "kernfs",
    srcs = [
        "dynamic_bytes_file.go",
        "fd_impl_util.go",
        "filesystem.go",
        "inode_impl_util.go",
        "kernfs.go",
        "slot_list.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fspath",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

go_test(
    name = "kernfs_test",
    size = "small",
    srcs = ["kernfs_test.go"],
    deps = [
        ":kernfs",
        "//pkg/abi/linux",
        "//pkg/fspath",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)
