load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "watchdog",
    srcs = ["watchdog.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/watchdog",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/time",
    ],
)
