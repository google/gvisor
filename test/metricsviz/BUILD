load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "metricsviz",
    srcs = [
        "metricsviz.go",
        "metricsviz_groups.go",
        "metricsviz_publish.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/metric",
        "//pkg/metric:metric_go_proto",
        "@com_github_docker_docker//api/types:go_default_library",
        "@com_github_go_echarts_go_echarts_v2//charts:go_default_library",
        "@com_github_go_echarts_go_echarts_v2//components:go_default_library",
        "@com_github_go_echarts_go_echarts_v2//opts:go_default_library",
        "@com_github_go_echarts_go_echarts_v2//types:go_default_library",
        "@org_golang_google_protobuf//encoding/protojson:go_default_library",
    ],
)
