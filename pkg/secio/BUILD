package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "secio",
    srcs = [
        "full_reader.go",
        "secio.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/secio",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "secio_test",
    size = "small",
    srcs = ["secio_test.go"],
    embed = [":secio"],
)
