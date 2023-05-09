load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "portforward",
    srcs = [
        "portforward.go",
        "portforward_fd_rw.go",
        "portforward_hostinet.go",
        "portforward_netstack.go",
        "portforward_test_util.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/sentry/vfs",
        "//pkg/tcpip",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "portforward_test",
    srcs = [
        "portforward_fd_rw_test.go",
        "portforward_hostinet_test.go",
        "portforward_netstack_test.go",
    ],
    library = ":portforward",
    tags = [
        "requires-net:ipv4",
        "requires-net:loopback",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/vfs",
        "//pkg/tcpip",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
