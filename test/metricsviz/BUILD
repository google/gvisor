load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricsviz",
    testonly = 1,
    srcs = [
        "metricsviz.go",
        "metricsviz_publish.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/metric",
        "//pkg/metric:metric_go_proto",
        "//pkg/test/dockerutil",
        "@com_github_go_echarts_go_echarts_v2//charts:go_default_library",
        "@com_github_go_echarts_go_echarts_v2//components:go_default_library",
        "@com_github_go_echarts_go_echarts_v2//opts:go_default_library",
        "@com_github_go_echarts_go_echarts_v2//types:go_default_library",
        "@org_golang_google_protobuf//encoding/protojson:go_default_library",
    ],
)
