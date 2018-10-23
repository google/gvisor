load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "device",
    srcs = ["device.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/proc/device",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/sentry/device"],
)
