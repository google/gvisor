load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "injector",
    srcs = [
        "certs.go",
        "webhook.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "@com_github_mattbaird_jsonpatch//:go_default_library",
        "@io_k8s_api//admission/v1beta1:go_default_library",
        "@io_k8s_api//admissionregistration/v1beta1:go_default_library",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/api/errors:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_client_go//kubernetes:go_default_library",
    ],
)
