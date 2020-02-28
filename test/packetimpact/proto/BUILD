#load("//net/grpc/go/build_defs:go_grpc_library.bzl", "go_grpc_library")
#load("//tools/build_defs/proto/cpp:cc_proto_library.bzl", "cc_proto_library")
#load("@rules_proto//proto:defs.bzl", "proto_library")
load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")

#load("@com_github_grpc_grpc//bazel:grpc_build_system.bzl", "grpc_proto_library")
#load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
#load("@org_golang_google_grpc//:go_default_library", "go_grpc_library")

#load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")
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

#go_proto_library(
#    name = "stub_go_proto",
#    compiler = "@io_bazel_rules_go//proto:go_grpc",
#    importpath = "gvisor/test/proto/stub",
#    proto = ":stub_proto",
#)

##cc_proto_library(
##    name = "stub_cc_proto",
##    deps = [":stub_proto"],
##)
##
##go_proto_library(
##    name = "stub_go_proto",
##    deps = [":stub_proto"],
##)

go_grpc_library(
    name = "stub_go_grpc_proto",
    importpath = "test/packetimpact/proto/stub_go_grpc_proto",
    protos = [":stub_proto"],
)

cc_grpc_library(
    name = "stub_cc_grpc_proto",
    srcs = [":stub_proto"],
    generate_mocks = False,
    grpc_only = True,
    #service_namespace = "grpc_gen",
    deps = [":stub_cc_proto"],
)
