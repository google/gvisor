load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "interrupt",
    srcs = [
        "interrupt.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/interrupt",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "interrupt_test",
    size = "small",
    srcs = ["interrupt_test.go"],
    embed = [":interrupt"],
)
