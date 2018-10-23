load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],  # Apache 2.0
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
        "pool.go",
        "server.go",
        "transport.go",
        "version.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/p9",
    deps = [
        "//pkg/fd",
        "//pkg/log",
        "//pkg/unet",
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
        "pool_test.go",
        "transport_test.go",
        "version_test.go",
    ],
    embed = [":p9"],
    deps = [
        "//pkg/fd",
        "//pkg/unet",
    ],
)
