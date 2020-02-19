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
        "endian_unsafe.go",
        "layers.go",
        "rawsockets.go",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/proto:stub_go_grpc_proto",
        "//test/packetimpact/proto:stub_go_proto",
        "@com_github_getlantern//deepcopy:go_default_library",
        "@com_github_google_go-cmp//cmp:go_default_library",
        "@com_github_google_go-cmp//cmp/cmpopts:go_default_library",
        "@com_github_imdario//mergo:go_default_library",
        "@org_golang_google//grpc:go_default_library",
        "@org_golang_google//grpc/keepalive:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
