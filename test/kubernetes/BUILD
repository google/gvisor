load("//tools:defs.bzl", "go_library", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "test_range_config",
    srcs = ["test_range_config.proto"],
    has_services = 0,
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "@com_google_protobuf//:any_proto",
    ],
)

go_library(
    name = "kubernetes",
    srcs = ["helpers.go"],
    visibility = [
        "//visibility:public",
    ],
)
