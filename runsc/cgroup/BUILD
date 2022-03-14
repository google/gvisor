load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "cgroup",
    srcs = [
        "cgroup.go",
        "cgroup_v2.go",
        "systemd.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/cleanup",
        "//pkg/log",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_coreos_go_systemd_v22//dbus:go_default_library",
        "@com_github_godbus_dbus_v5//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sync//errgroup:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "cgroup_test",
    size = "small",
    srcs = [
        "cgroup_test.go",
        "cgroup_v2_test.go",
        "systemd_test.go",
    ],
    library = ":cgroup",
    tags = ["local"],
    deps = [
        "//pkg/test/testutil",
        "@com_github_coreos_go_systemd_v22//dbus:go_default_library",
        "@com_github_godbus_dbus_v5//:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
