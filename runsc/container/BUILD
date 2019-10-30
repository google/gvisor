load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "container",
    srcs = [
        "container.go",
        "hook.go",
        "state_file.go",
        "status.go",
    ],
    importpath = "gvisor.dev/gvisor/runsc/container",
    visibility = [
        "//runsc:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/sentry/control",
        "//runsc/boot",
        "//runsc/cgroup",
        "//runsc/sandbox",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_gofrs_flock//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "container_test",
    size = "medium",
    srcs = [
        "console_test.go",
        "container_test.go",
        "multi_container_test.go",
        "shared_volume_test.go",
    ],
    data = [
        "//runsc",
        "//runsc/container/test_app",
    ],
    embed = [":container"],
    shard_count = 5,
    tags = [
        "requires-kvm",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/unet",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/boot/platforms",
        "//runsc/specutils",
        "//runsc/testutil",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_kr_pty//:go_default_library",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
