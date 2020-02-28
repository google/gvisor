load("//tools:defs.bzl", "cc_binary")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

cc_binary(
    name = "stub",
    srcs = ["stub.cc"],
    # This is needed for running in a docker container.
    linkopts = [
        "-static",
        "-lstdc++",
    ],  # security: disable=cc-static-no-pie
    linkstatic = 1,
    deps = [
        "//test/packetimpact/proto:stub_cc_grpc_proto",
        "//test/packetimpact/proto:stub_cc_proto",
        "@com_github_grpc_grpc//:grpc++",
    ],
)
