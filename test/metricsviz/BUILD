load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricsviz",
    srcs = ["metricsviz.go"],
    deps = [
        "//pkg/metric",
        "//pkg/metric:metric_go_proto",
        "@org_golang_google_protobuf//encoding/protojson:go_default_library",
    ],
)
