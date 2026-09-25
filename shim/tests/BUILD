load("//tools:defs.bzl", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_test(
    name = "shim_test",
    srcs = [
        "gvisor_task_service_test.go",
        "metric_server_test.go",
        "shim_test.go",
    ],
    deps = [
        "//pkg/shim/v1/taskserver:task_server_go_proto",
        "//shim/shimutils",
        "@com_github_containerd_containerd_api//events:go_default_library",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_api//types/task:go_default_library",
        "@com_github_containerd_ttrpc//:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_protobuf//types/known/anypb:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
    ],
)

go_test(
    name = "lifecycle_benchmark_test",
    size = "large",
    srcs = ["lifecycle_bench_test.go"],
    args = [
        "-test.bench=.",
        "-test.run=^$$",
        "-test.benchtime=30x",
        "-test.v",
        "--test_platforms=kvm,systrap",
    ],
    data = [
        "//:release",
    ],
    tags = [
        "manual",
        "requires-kvm",
    ],
    deps = [
        "//pkg/log",
        "//pkg/test/testutil",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "//shim/shimutils",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
