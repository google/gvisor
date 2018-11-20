load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0, portions BSD, MIT

go_library(
    name = "safecopy",
    srcs = [
        "atomic_amd64.s",
        "memclr_amd64.s",
        "memcpy_amd64.s",
        "safecopy.go",
        "safecopy_unsafe.go",
        "sighandler_amd64.s",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/safecopy",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/syserror",
    ],
)

go_test(
    name = "safecopy_test",
    srcs = [
        "safecopy_test.go",
    ],
    embed = [":safecopy"],
)
