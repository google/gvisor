load("//tools:defs.bzl", "go_library", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "fscheckpoint_proto",
    srcs = ["fscheckpoint.proto"],
    visibility = ["//pkg/sentry:internal"],
)

go_library(
    name = "fscheckpoint",
    srcs = ["fscheckpoint.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        ":fscheckpoint_proto_go_proto",
        "//pkg/sentry/checkpoint",
    ],
)
