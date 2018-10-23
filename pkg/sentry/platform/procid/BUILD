load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "procid",
    srcs = [
        "procid.go",
        "procid_amd64.s",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/procid",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "procid_test",
    size = "small",
    srcs = [
        "procid_test.go",
    ],
    embed = [":procid"],
)

go_test(
    name = "procid_net_test",
    size = "small",
    srcs = [
        "procid_net_test.go",
        "procid_test.go",
    ],
    embed = [":procid"],
)
