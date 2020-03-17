load("//tools:defs.bzl", "go_library")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

go_library(
    name = "testbench",
    srcs = [
        "connections.go",
        "dut.go",
        "dut_client.go",
        "layers.go",
        "rawsockets.go",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/usermem",
        "//test/packetimpact/proto:posix_server_go_proto",
        "@com_github_google_go-cmp//cmp:go_default_library",
        "@com_github_google_go-cmp//cmp/cmpopts:go_default_library",
        "@com_github_imdario_mergo//:go_default_library",
        "@com_github_mohae_deepcopy//:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//keepalive:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
