package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_stateify", "go_test")

go_stateify(
    name = "pipe_state",
    srcs = [
        "pipe.go",
        "pipe_state.go",
    ],
    out = "pipe_autogen_state.go",
    imports = ["gvisor.googlesource.com/gvisor/pkg/sentry/fs"],
    package = "fdpipe",
)

go_library(
    name = "fdpipe",
    srcs = [
        "pipe.go",
        "pipe_autogen_state.go",
        "pipe_opener.go",
        "pipe_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/fdpipe",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/p9",
        "//pkg/refs",
        "//pkg/secio",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/transport/unix",
        "//pkg/unet",
        "//pkg/waiter",
        "//pkg/waiter/fdnotifier",
    ],
)

go_test(
    name = "fdpipe_test",
    size = "small",
    srcs = [
        "pipe_opener_test.go",
        "pipe_test.go",
    ],
    embed = [":fdpipe"],
    deps = [
        "//pkg/fd",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "//pkg/waiter/fdnotifier",
        "@com_github_google_uuid//:go_default_library",
    ],
)
