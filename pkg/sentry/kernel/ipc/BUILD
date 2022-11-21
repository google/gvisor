load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "ipc",
    srcs = [
        "ns.go",
        "object.go",
        "registry.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
