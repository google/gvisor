load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "rawfile",
    srcs = [
        "blockingpoll_amd64.s",
        "blockingpoll_arm64.s",
        "blockingpoll_noyield_unsafe.go",
        "blockingpoll_yield_unsafe.go",
        "errors.go",
        "rawfile_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "rawfile_test",
    srcs = [
        "errors_test.go",
    ],
    library = "rawfile",
    deps = [
        "//pkg/tcpip",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
