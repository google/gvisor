load("//tools:defs.bzl", "go_library", "proto_library")

package(licenses = ["notice"])

proto_library(
    name = "api",
    srcs = [
        "runtimeoptions.proto",
    ],
)

go_library(
    name = "runtimeoptions",
    srcs = ["runtimeoptions.go"],
    visibility = ["//pkg/shim/v2:__pkg__"],
    deps = [
        "//pkg/shim/v2/runtimeoptions:api_go_proto",
        "@com_github_gogo_protobuf//proto:go_default_library",
    ],
)
