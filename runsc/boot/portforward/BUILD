load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "portforward",
    srcs = [
        "portforward.go",
        "portforward_fd_rw.go",
        "portforward_hostinet.go",
    ],
    deps = [
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/log",
        "//pkg/sentry/vfs",
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
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
