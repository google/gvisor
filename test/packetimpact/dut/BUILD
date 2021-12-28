load("//tools:defs.bzl", "cc_binary", "go_library", "grpcpp")

package(
    licenses = ["notice"],
)

cc_binary(
    name = "posix_server",
    srcs = ["posix_server.cc"],
    visibility = ["//test/packetimpact:__subpackages__"],
    deps = [
        grpcpp,
        "//test/packetimpact/proto:posix_server_cc_grpc_proto",
        "//test/packetimpact/proto:posix_server_cc_proto",
        "@com_google_absl//absl/strings:str_format",
    ],
)

go_library(
    name = "dut",
    testonly = True,
    srcs = ["dut.go"],
    visibility = [
        "//test/packetimpact:__subpackages__",
        "//turquoise/connectivity/netstack/gvisor_tests/packetimpact:__subpackages__",
    ],
    deps = [
        "//test/packetimpact/testbench",
        "@org_golang_x_sync//errgroup:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
