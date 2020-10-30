load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "cli",
    srcs = ["cli.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//webhook/pkg/injector",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/util/net:go_default_library",
        "@io_k8s_client_go//kubernetes:go_default_library",
        "@io_k8s_client_go//rest:go_default_library",
    ],
)
