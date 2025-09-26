load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stateio",
    srcs = [
        "bufio.go",
        "fdreader.go",
        "fdwriter.go",
        "pagesfile.go",
        "stateio.go",
        "stateio_impl_util.go",
        "stateio_util_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/aio",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/memmap",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
