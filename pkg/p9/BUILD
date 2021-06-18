load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "p9",
    srcs = [
        "buffer.go",
        "client.go",
        "client_file.go",
        "file.go",
        "handlers.go",
        "messages.go",
        "p9.go",
        "path_tree.go",
        "server.go",
        "transport.go",
        "transport_flipcall.go",
        "version.go",
    ],
    deps = [
        "//pkg/abi/linux/errno",
        "//pkg/errors",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/fdchannel",
        "//pkg/flipcall",
        "//pkg/log",
        "//pkg/pool",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "p9_test",
    size = "small",
    srcs = [
        "buffer_test.go",
        "client_test.go",
        "messages_test.go",
        "p9_test.go",
        "transport_test.go",
        "version_test.go",
    ],
    library = ":p9",
    deps = [
        "//pkg/fd",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
