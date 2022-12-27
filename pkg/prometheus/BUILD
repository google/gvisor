load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "prometheus",
    srcs = [
        "prometheus.go",
    ],
    visibility = ["//:sandbox"],
)

go_test(
    name = "prometheus_test",
    srcs = ["prometheus_test.go"],
    library = ":prometheus",
    deps = [
        "//pkg/metric:metric_go_proto",
        "@com_github_golang_protobuf//proto:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_prometheus_common//expfmt",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_google_protobuf//reflect/protoreflect:go_default_library",
        "@org_golang_google_protobuf//testing/protocmp:go_default_library",
    ],
)
