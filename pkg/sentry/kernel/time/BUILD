load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "timer_mutex",
    out = "timer_mutex.go",
    package = "time",
    prefix = "timer",
    substrs = {
        "genericMark": "timer",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_library(
    name = "time",
    srcs = [
        "context.go",
        "time.go",
        "timer_mutex.go",
        "util.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/waiter",
    ],
)
