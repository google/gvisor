load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sighandling",
    srcs = [
        "sighandling.go",
        "sighandling_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/sighandling",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/abi/linux"],
)
