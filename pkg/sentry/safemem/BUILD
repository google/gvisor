load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "safemem",
    srcs = [
        "block_unsafe.go",
        "io.go",
        "safemem.go",
        "seq_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/safemem",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/platform/safecopy",
    ],
)

go_test(
    name = "safemem_test",
    size = "small",
    srcs = [
        "io_test.go",
        "seq_test.go",
    ],
    embed = [":safemem"],
)
