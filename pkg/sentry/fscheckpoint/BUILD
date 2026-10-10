load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

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

go_test(
    name = "fscheckpoint_test",
    srcs = ["fscheckpoint_test.go"],
    embed = [":fscheckpoint"],
    deps = [
        "//pkg/sentry/checkpoint",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)
