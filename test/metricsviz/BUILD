load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricsviz",
    testonly = 1,
    srcs = ["metricsviz.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/metric",
        "//pkg/metric:metric_go_proto",
        "//pkg/test/dockerutil",
        "@org_golang_google_protobuf//encoding/protojson:go_default_library",
    ],
)
