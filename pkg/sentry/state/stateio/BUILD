load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stateio",
    srcs = [
        "bufio.go",
        "bufreader.go",
        "bufwriter.go",
        "fdreader.go",
        "fdwriter.go",
        "ioreader.go",
        "iowriter.go",
        "pagesfile.go",
        "stateio.go",
        "stateio_impl_util.go",
        "stateio_util.go",
        "stateio_util_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/aio",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/memutil",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/memmap",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "stateio_test",
    size = "small",
    srcs = [
        "bufreader_test.go",
        "bufwriter_test.go",
        "ioreader_test.go",
        "iowriter_test.go",
    ],
    library = ":stateio",
    deps = [
        "//pkg/cleanup",
        "//pkg/rand",
        "//pkg/sentry/memmap",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
