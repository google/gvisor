load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "testcluster",
    srcs = [
        "client.go",
        "objects.go",
        "testcluster.go",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/log",
        "//pkg/rand",
        "//pkg/sync",
        "//test/kubernetes:test_range_config_go_proto",
        "@io_k8s_api//apps/v1:go_default_library",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/api/resource:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_client_go//kubernetes:go_default_library",
        "@io_k8s_client_go//tools/clientcmd:go_default_library",
        "@org_golang_google_genproto//googleapis/container/v1:container",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
