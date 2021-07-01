load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(licenses = ["notice"])

go_library(
    name = "eventchannel",
    srcs = [
        "event.go",
        "event_any.go",
        "rate.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        ":eventchannel_go_proto",
        "//pkg/errors/linuxerr",
        "//pkg/log",
        "//pkg/sync",
        "//pkg/unet",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_google_protobuf//types/known/anypb:go_default_library",
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
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
