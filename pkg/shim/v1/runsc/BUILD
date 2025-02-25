load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "runsc",
    srcs = [
        "api.go",
        "debug.go",
        "epoll.go",
        "oom_v2.go",
        "options.go",
        "service.go",
        "service_linux.go",
        "state.go",
    ],
    visibility = ["//pkg/shim:__subpackages__"],
    deps = [
        "//pkg/cleanup",
        "//pkg/shim/v1/extension",
        "//pkg/shim/v1/proc",
        "//pkg/shim/v1/runsccmd",
        "//pkg/shim/v1/runtimeoptions",
        "//pkg/shim/v1/runtimeoptions/v14",
        "//pkg/shim/v1/utils",
        "//runsc/specutils",
        "@com_github_burntsushi_toml//:go_default_library",
        "@com_github_containerd_cgroups//:go_default_library",
        "@com_github_containerd_cgroups//stats/v1:go_default_library",
        "@com_github_containerd_cgroups//v2:go_default_library",
        "@com_github_containerd_cgroups//v2/stats:go_default_library",
        "@com_github_containerd_console//:go_default_library",
        "@com_github_containerd_containerd//api/events:go_default_library",
        "@com_github_containerd_containerd//api/types/task:go_default_library",
        "@com_github_containerd_containerd//events:go_default_library",
        "@com_github_containerd_containerd//mount:go_default_library",
        "@com_github_containerd_containerd//namespaces:go_default_library",
        "@com_github_containerd_containerd//pkg/process:go_default_library",
        "@com_github_containerd_containerd//pkg/stdio:go_default_library",
        "@com_github_containerd_containerd//runtime:go_default_library",
        "@com_github_containerd_containerd//runtime/linux/runctypes:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/shim:go_default_library",
        "@com_github_containerd_containerd//runtime/v2/task:go_default_library",
        "@com_github_containerd_containerd//sys/reaper:go_default_library",
        "@com_github_containerd_errdefs//:go_default_library",
        "@com_github_containerd_fifo//:go_default_library",
        "@com_github_containerd_go_runc//:go_default_library",
        "@com_github_containerd_log//:go_default_library",
        "@com_github_containerd_typeurl//:go_default_library",
        "@com_github_gogo_protobuf//types:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_sirupsen_logrus//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "runsc_test",
    srcs = ["service_test.go"],
    library = ":runsc",
    deps = [
        "//pkg/shim/v1/utils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
