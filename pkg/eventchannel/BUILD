load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(licenses = ["notice"])

go_library(
    name = "eventchannel",
    srcs = [
        "event.go",
        "rate.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        ":eventchannel_go_proto",
        "//pkg/log",
        "//pkg/sync",
        "//pkg/unet",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_golang_protobuf//ptypes:go_default_library_gen",
        "@org_golang_x_time//rate:go_default_library",
    ],
)

proto_library(
    name = "eventchannel",
    srcs = ["event.proto"],
    visibility = ["//:sandbox"],
)

go_test(
    name = "eventchannel_test",
    srcs = ["event_test.go"],
    library = ":eventchannel",
    deps = [
        "//pkg/sync",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)
