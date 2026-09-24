load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "hostfd",
    srcs = [
        "hostfd.go",
        "hostfd_linux.go",
        "hostfd_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/safemem",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "hostfd_test",
    size = "small",
    srcs = ["hostfd_test.go"],
    library = ":hostfd",
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
