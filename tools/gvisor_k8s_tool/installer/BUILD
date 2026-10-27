load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "installer",
    srcs = [
        "activation.go",
        "config.go",
        "containerd.go",
        "cri.go",
        "generation.go",
        "health.go",
        "hostexec.go",
        "installer.go",
        "lock.go",
        "logging.go",
        "node.go",
        "payload.go",
        "preflight.go",
        "runscconfig.go",
        "state.go",
    ],
    importpath = "gvisor.dev/gvisor/tools/gvisor_k8s_tool/installer",
    deps = [
        "@com_github_burntsushi_toml//:go_default_library",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/types:go_default_library",
        "@io_k8s_client_go//kubernetes:go_default_library",
        "@io_k8s_cri_api//pkg/apis/runtime/v1:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_grpc//codes:go_default_library",
        "@org_golang_google_grpc//credentials/insecure:go_default_library",
        "@org_golang_google_grpc//status:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "installer_test",
    size = "small",
    srcs = [
        "config_test.go",
        "containerd_test.go",
        "cri_test.go",
        "installer_test.go",
        "node_test.go",
        "runscconfig_test.go",
    ],
    embed = [":installer"],
    deps = [
        "@com_github_burntsushi_toml//:go_default_library",
        "@io_k8s_api//core/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/apis/meta/v1:go_default_library",
        "@io_k8s_apimachinery//pkg/types:go_default_library",
        "@io_k8s_client_go//kubernetes/fake:go_default_library",
        "@io_k8s_cri_api//pkg/apis/runtime/v1:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
    ],
)
