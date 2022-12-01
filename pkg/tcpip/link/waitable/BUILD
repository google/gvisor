load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "waitable",
    srcs = [
        "waitable.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "waitable_test",
    srcs = [
        "waitable_test.go",
    ],
    library = ":waitable",
    deps = [
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)
