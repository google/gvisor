package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "shm_state",
    srcs = [
        "shm.go",
    ],
    out = "shm_autogen_state.go",
    package = "shm",
)

go_library(
    name = "shm",
    srcs = [
        "device.go",
        "shm.go",
        "shm_autogen_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/shm",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
    ],
)
