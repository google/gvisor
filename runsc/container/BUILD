load("//tools:defs.bzl", "go_library", "go_test", "more_shards")

package(licenses = ["notice"])

go_library(
    name = "container",
    srcs = [
        "container.go",
        "hook.go",
        "state_file.go",
        "status.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/sighandling",
        "//pkg/sync",
        "//runsc/boot",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/console",
        "//runsc/sandbox",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_gofrs_flock//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "container_test",
    size = "large",
    srcs = [
        "console_test.go",
        "container_norace_test.go",
        "container_race_test.go",
        "container_test.go",
        "multi_container_test.go",
        "shared_volume_test.go",
    ],
    data = [
        "//runsc",
        "//test/cmd/test_app",
    ],
    library = ":container",
    shard_count = more_shards,
    tags = [
        "requires-kvm",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sync",
        "//pkg/test/testutil",
        "//pkg/unet",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/boot/platforms",
        "//runsc/config",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_kr_pty//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
