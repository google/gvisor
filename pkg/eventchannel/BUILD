package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

go_library(
    name = "eventchannel",
    srcs = [
        "event.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/eventchannel",
    visibility = ["//:sandbox"],
    deps = [
        ":eventchannel_go_proto",
        "//pkg/log",
        "//pkg/unet",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_golang_protobuf//ptypes:go_default_library",
    ],
)

proto_library(
    name = "eventchannel_proto",
    srcs = ["event.proto"],
    visibility = ["//:sandbox"],
)

go_proto_library(
    name = "eventchannel_go_proto",
    importpath = "gvisor.googlesource.com/gvisor/pkg/eventchannel/eventchannel_go_proto",
    proto = ":eventchannel_proto",
    visibility = ["//:sandbox"],
)
