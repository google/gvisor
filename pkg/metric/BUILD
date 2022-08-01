load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(licenses = ["notice"])

go_library(
    name = "metric",
    srcs = [
        "condmetric_profiling.go",
        "condmetric_profiling_fake.go",
        "fake_metric.go",
        "metric.go",
        "metric_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        ":metric_go_proto",
        "//pkg/atomicbitops",
        "//pkg/eventchannel",
        "//pkg/gohacks",
        "//pkg/log",
        "//pkg/sync",
        "@org_golang_google_protobuf//types/known/timestamppb",
    ],
)

proto_library(
    name = "metric",
    srcs = ["metric.proto"],
    visibility = ["//:sandbox"],
    deps = [
        "@com_google_protobuf//:timestamp_proto",
    ],
)

go_test(
    name = "metric_test",
    srcs = [
        "metric_test.go",
        "utils_test.go",
    ],
    library = ":metric",
    deps = [
        ":metric_go_proto",
        "//pkg/eventchannel",
        "//pkg/sync",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)

go_test(
    name = "condmetric_test",
    srcs = [
        "condmetric_profiling_disabled_test.go",
        "condmetric_profiling_enabled_test.go",
        "utils_test.go",
    ],
    library = ":metric",
    deps = [
        ":metric_go_proto",
        "//pkg/eventchannel",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
