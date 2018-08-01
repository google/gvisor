package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "usage",
    srcs = [
        "cpu.go",
        "io.go",
        "memory.go",
        "memory_unsafe.go",
        "usage.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/usage",
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        "//pkg/bits",
        "//pkg/sentry/memutil",
    ],
)
