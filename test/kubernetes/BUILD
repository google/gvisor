load("//tools:defs.bzl", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "test_range_config",
    srcs = ["test_range_config.proto"],
    has_services = 1,
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "@googleapis//google/container/v1:container_proto",
    ],
)
