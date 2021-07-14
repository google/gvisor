load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "shm_refs",
    out = "shm_refs.go",
    consts = {
        "enableLogging": "true",
    },
    package = "shm",
    prefix = "Shm",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "Shm",
    },
)

go_library(
    name = "shm",
    srcs = [
        "device.go",
        "shm.go",
        "shm_refs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/ipc",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)
