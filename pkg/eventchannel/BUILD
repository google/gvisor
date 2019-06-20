load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

package(licenses = ["notice"])

go_library(
    name = "eventchannel",
    srcs = [
        "event.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/eventchannel",
    visibility = ["//:sandbox"],
    deps = [
        ":eventchannel_go_proto",
        "//pkg/log",
        "//pkg/unet",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_golang_protobuf//ptypes:go_default_library_gen",
    ],
)

proto_library(
    name = "eventchannel_proto",
    srcs = ["event.proto"],
)

go_proto_library(
    name = "eventchannel_go_proto",
    importpath = "gvisor.dev/gvisor/pkg/eventchannel/eventchannel_go_proto",
    proto = ":eventchannel_proto",
    visibility = ["//:sandbox"],
)
