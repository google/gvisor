package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "binder_state",
    srcs = ["binder.go"],
    out = "binder_state.go",
    package = "binder",
)

go_library(
    name = "binder",
    srcs = [
        "binder.go",
        "binder_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/binder",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/tcpip/transport/unix",
    ],
)
