load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sighandling",
    srcs = [
        "sighandling.go",
        "sighandling_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/sighandling",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/abi/linux"],
)
