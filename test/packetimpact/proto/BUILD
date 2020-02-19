load("//tools:defs.bzl", "proto_library")
load("//net/grpc:cc_grpc_library.bzl", "cc_grpc_library")
load("//net/grpc/go/build_defs:go_grpc_library.bzl", "go_grpc_library")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

proto_library(
    name = "stub",
    srcs = ["stub.proto"],
    has_services = 1,
)

cc_grpc_library(
    name = "stub_cc_grpc_proto",
    srcs = [":stub_proto"],
    deps = [":stub_cc_proto"],
)

go_grpc_library(
    name = "stub_go_grpc_proto",
    srcs = [":stub_proto"],
    deps = [":stub_go_proto"],
)
