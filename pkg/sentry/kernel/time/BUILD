load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "time",
    srcs = [
        "context.go",
        "time.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/time",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
