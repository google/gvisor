load("//tools:defs.bzl", "default_platform", "go_library", "go_test", "more_shards", "platforms")

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
        "//pkg/sighandling",
        "//pkg/sync",
        "//runsc/boot",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/console",
        "//runsc/donation",
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
        "container_test.go",
        "multi_container_test.go",
        "shared_volume_test.go",
        "trace_test.go",
    ],
    # Only run the default platform for the tsan test, which should
    # be compatible. For non-tsan builds, run all platforms.
    args = select({
        "//conditions:default": [
            "--test_platforms=%s" % ",".join([p for (p, tags) in platforms.items() if "manual" not in tags]) or default_platform,
        ],
        "//tools:gotsan": [
            "--test_platforms=%s" % default_platform,
        ],
    }),
    data = [
        "//runsc",
        "//test/cmd/test_app",
    ],
    library = ":container",
    shard_count = more_shards,
    tags = ["requires-kvm"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/limits",
        "//pkg/sentry/platform",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/remote/test",
        "//pkg/sync",
        "//pkg/test/testutil",
        "//pkg/unet",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_kr_pty//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
