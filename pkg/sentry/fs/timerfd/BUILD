package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify")

go_stateify(
    name = "timerfd_state",
    srcs = [
        "timerfd.go",
    ],
    out = "timerfd_state.go",
    package = "timerfd",
)

go_library(
    name = "timerfd",
    srcs = [
        "timerfd.go",
        "timerfd_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/timerfd",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)
