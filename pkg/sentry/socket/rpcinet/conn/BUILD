load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "conn",
    srcs = ["conn.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/conn",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/binary",
        "//pkg/sentry/socket/rpcinet:syscall_rpc_go_proto",
        "//pkg/syserr",
        "//pkg/unet",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)
