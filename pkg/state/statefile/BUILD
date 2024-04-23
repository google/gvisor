load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "statefile",
    srcs = [
        "async_io.go",
        "statefile.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/compressio",
        "//pkg/fd",
        "//pkg/sync",
    ],
)

go_test(
    name = "statefile_test",
    size = "small",
    srcs = [
        "async_io_test.go",
        "statefile_test.go",
    ],
    library = ":statefile",
    deps = [
        "//pkg/compressio",
        "//pkg/fd",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
