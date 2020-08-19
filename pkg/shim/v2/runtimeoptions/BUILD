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
    deps = [":api_go_proto"],
)

go_test(
    name = "runtimeoptions_test",
    size = "small",
    srcs = ["runtimeoptions_test.go"],
    library = ":runtimeoptions",
    deps = [
        "@com_github_containerd_containerd//runtime/v1/shim/v1:go_default_library",
        "@com_github_containerd_typeurl//:go_default_library",
        "@com_github_golang_protobuf//proto:go_default_library",
    ],
)
