load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stateio",
    srcs = [
        "bufreader.go",
        "fdreader.go",
        "ioreader.go",
        "stateio.go",
        "stateio_impl_util.go",
        "stateio_impl_util_unsafe.go",
        "stateio_util.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/aio",
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
        "ioreader_test.go",
    ],
    library = ":stateio",
    deps = [
        "//pkg/rand",
        "//pkg/sentry/memmap",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
