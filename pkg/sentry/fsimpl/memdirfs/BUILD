load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "memdirfs",
    prefix = "Dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Dentry",
        "Linker": "*Dentry",
    },
)

go_library(
    name = "memdirfs",
    srcs = [
        "dentry_list.go",
        "directory.go",
        "dynamic_bytes_file.go",
        "filesystem.go",
        "memdirfs.go",
        "symlink.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/memdirfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

go_test(
    name = "memdirfs_test",
    size = "small",
    srcs = ["memdirfs_test.go"],
    deps = [
        ":memdirfs",
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)
