load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "tpuproxy",
    srcs = ["tpu.go"],
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/arch",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
