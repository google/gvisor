load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "lisafs",
    srcs = [
        "channel.go",
        "client.go",
        "connection.go",
        "fd.go",
        "handlers.go",
        "lisafs.go",
        "message.go",
        "server.go",
        "sock.go",
    ],
    marshal = True,
    deps = [
        "//pkg/fdchannel",
        "//pkg/flipcall",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/p9",
        "//pkg/refsvfs2",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "sock_test",
    size = "small",
    srcs = ["sock_test.go"],
    library = ":lisafs",
    deps = [
        "//pkg/lisafs/test",
        "//pkg/marshal",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "connection_test",
    size = "small",
    srcs = ["connection_test.go"],
    deps = [
        ":lisafs",
        "//pkg/lisafs/test",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
