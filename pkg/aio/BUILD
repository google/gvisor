load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "aio",
    srcs = [
        "aio.go",
        "aio_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "aio_test",
    size = "small",
    srcs = ["aio_test.go"],
    library = ":aio",
    deps = [
        "//pkg/bitmap",
        "//pkg/rand",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
