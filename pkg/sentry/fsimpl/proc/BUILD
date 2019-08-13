load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "proc",
    prefix = "dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*dentry",
        "Linker": "*dentry",
    },
)

go_library(
    name = "proc",
    srcs = [
        "dentry.go",
        "dentry_list.go",
        "file_description.go",
        "filesystems.go",
        "loadavg.go",
        "meminfo.go",
        "mounts.go",
        "net.go",
        "proc.go",
        "stat.go",
        "sys.go",
        "task.go",
        "version.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/proc",
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/limits",
        "//pkg/sentry/mm",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

go_test(
    name = "proc_test",
    size = "small",
    srcs = ["net_test.go"],
    embed = [":proc"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/inet",
    ],
)
