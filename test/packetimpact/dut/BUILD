load("//tools:defs.bzl", "cc_binary", "grpcpp")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

cc_binary(
    name = "posix_server",
    srcs = ["posix_server.cc"],
    linkstatic = 1,
    static = True,  # This is needed for running in a docker container.
    deps = [
        grpcpp,
        "//test/packetimpact/proto:posix_server_cc_grpc_proto",
        "//test/packetimpact/proto:posix_server_cc_proto",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_binary(
    name = "posix_server_dynamic",
    srcs = ["posix_server.cc"],
    deps = [
        grpcpp,
        "//test/packetimpact/proto:posix_server_cc_grpc_proto",
        "//test/packetimpact/proto:posix_server_cc_proto",
        "@com_google_absl//absl/strings:str_format",
    ],
)
