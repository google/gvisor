load("//tools:defs.bzl", "cc_binary", "grpcpp")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

cc_binary(
    name = "stub",
    srcs = ["stub.cc"],
    linkstatic = 1,
    static = True,  # This is needed for running in a docker container.
    deps = [
        grpcpp,
        "//test/packetimpact/proto:stub_cc_grpc_proto",
        "//test/packetimpact/proto:stub_cc_proto",
    ],
)
