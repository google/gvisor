load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "vfs2",
    srcs = [
        "linux64.go",
        "linux64_override_amd64.go",
        "linux64_override_arm64.go",
        "sys_read.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel",
        "//pkg/sentry/syscalls",
        "//pkg/sentry/syscalls/linux",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
