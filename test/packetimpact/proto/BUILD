load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")
load("//tools:defs.bzl", "proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_grpc_library")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

proto_library(
    name = "stub",
    srcs = ["stub.proto"],
)

cc_grpc_library(
    name = "stub_cc_grpc_proto",
    srcs = [":stub_proto"],
    generate_mocks = False,
    grpc_only = True,
    #service_namespace = "grpc_gen",
    deps = [":stub_cc_proto"],
)

go_grpc_library(
    name = "stub_go_grpc_proto",
    importpath = "test/packetimpact/proto/stub_go_grpc_proto",
    protos = [":stub_proto"],
)
