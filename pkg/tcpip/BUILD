load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "sock_err_list",
    out = "sock_err_list.go",
    package = "tcpip",
    prefix = "sockError",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*SockError",
        "Linker": "*SockError",
    },
)

go_library(
    name = "tcpip",
    srcs = [
        "sock_err_list.go",
        "socketops.go",
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
