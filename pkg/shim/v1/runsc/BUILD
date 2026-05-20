load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

proto_library(
    name = "hibernate",
    srcs = ["hibernate.proto"],
    has_services = True,
    visibility = [
        "//cloud/kubernetes/node/snapshot:__subpackages__",
        "//pkg/shim:__subpackages__",
    ],
)

go_library(
    name = "runsc",
    srcs = [
        "api.go",
        "container.go",
        "debug.go",
        "epoll.go",
        "hibernate.go",
        "hibernate_impl.go",
        "oom_v2.go",
        "options.go",
        "service.go",
        "service_linux.go",
        "state.go",
    ],
    visibility = ["//pkg/shim:__subpackages__"],
    deps = [
        ":hibernate_go_proto",
        "//pkg/cleanup",
        "//pkg/shim/v1/extension",
        "//pkg/shim/v1/proc",
        "//pkg/shim/v1/runsccmd",
        "//pkg/shim/v1/runtimeoptions",
        "//pkg/shim/v1/utils",
        "//runsc/specutils",
        "@com_github_burntsushi_toml//:go_default_library",
        "@com_github_containerd_cgroups_v3//:go_default_library",
        "@com_github_containerd_cgroups_v3//cgroup1:go_default_library",
        "@com_github_containerd_cgroups_v3//cgroup1/stats:go_default_library",  # keep
        "@com_github_containerd_cgroups_v3//cgroup2:go_default_library",
        "@com_github_containerd_cgroups_v3//cgroup2/stats:go_default_library",  # keep
        "@com_github_containerd_console//:go_default_library",
        "@com_github_containerd_containerd_api//events:go_default_library",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_api//types/runc/options:go_default_library",
        "@com_github_containerd_containerd_api//types/task:go_default_library",
        "@com_github_containerd_containerd_v2//cmd/containerd-shim-runc-v2/process:go_default_library",
        "@com_github_containerd_containerd_v2//core/events:go_default_library",
        "@com_github_containerd_containerd_v2//core/mount:go_default_library",
        "@com_github_containerd_containerd_v2//core/runtime:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/namespaces:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/protobuf:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/protobuf/types:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/shim:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/shutdown:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/stdio:go_default_library",
        "@com_github_containerd_containerd_v2//pkg/sys/reaper:go_default_library",
        "@com_github_containerd_errdefs//:go_default_library",
        "@com_github_containerd_errdefs_pkg//errgrpc:go_default_library",
        "@com_github_containerd_fifo//:go_default_library",
        "@com_github_containerd_go_runc//:go_default_library",
        "@com_github_containerd_log//:go_default_library",
        "@com_github_containerd_ttrpc//:go_default_library",
        "@com_github_containerd_typeurl_v2//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_sirupsen_logrus//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "runsc_test",
    srcs = [
        "oom_v2_test.go",
        "service_test.go",
        "state_test.go",
    ],
    library = ":runsc",
    deps = [
        "//pkg/shim/v1/utils",
        "@com_github_containerd_cgroups_v3//cgroup2:go_default_library",
        "@com_github_containerd_containerd_api//runtime/task/v2:go_default_library",
        "@com_github_containerd_containerd_v2//core/events:go_default_library",
        "@com_github_containerd_containerd_v2//core/runtime:go_default_library",
        "@com_github_containerd_errdefs//:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
