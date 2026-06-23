load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "shim_test",
    srcs = [
        "metric_server_test.go",
        "shim_test.go",
    ],
    deps = [
        "//runsc/specutils",
        "//shim/shimutils",
        "@com_github_containerd_containerd_api//events:go_default_library",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_api//types/task:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_protobuf//types/known/anypb:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)
