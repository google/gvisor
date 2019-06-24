load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "control",
    srcs = [
        "control.go",
        "logging.go",
        "pprof.go",
        "proc.go",
        "state.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/control",
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/host",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/state",
        "//pkg/sentry/strace",
        "//pkg/sentry/usage",
        "//pkg/sentry/watchdog",
        "//pkg/tcpip/link/sniffer",
        "//pkg/urpc",
    ],
)

go_test(
    name = "control_test",
    size = "small",
    srcs = ["proc_test.go"],
    embed = [":control"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/usage",
    ],
)
