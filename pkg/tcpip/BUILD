load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tcpip",
    srcs = [
        "tcpip.go",
        "time_unsafe.go",
        "timer.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip/buffer",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tcpip_test",
    size = "small",
    srcs = ["tcpip_test.go"],
    library = ":tcpip",
)

go_test(
    name = "tcpip_x_test",
    size = "small",
    srcs = ["timer_test.go"],
    deps = [":tcpip"],
)
