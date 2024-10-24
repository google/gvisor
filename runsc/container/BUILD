load("//tools:defs.bzl", "default_platform", "go_library", "go_test", "most_shards", "platforms")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

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
        "//pkg/sentry/fsimpl/erofs",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/pgalloc",
        "//pkg/sighandling",
        "//pkg/state/statefile",
        "//pkg/sync",
        "//pkg/unet",
        "//pkg/urpc",
        "//runsc/boot",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/console",
        "//runsc/donation",
        "//runsc/profile",
        "//runsc/sandbox",
        "//runsc/specutils",
        "//runsc/starttime",
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
        "metric_server_test.go",
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
    shard_count = most_shards,
    tags = ["requires-kvm"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bits",
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/sentry/control",
        "//pkg/sentry/fsimpl/erofs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/limits",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/seccheck/sinks/remote/test",
        "//pkg/state/statefile",
        "//pkg/sync",
        "//pkg/test/testutil",
        "//pkg/unet",
        "//runsc/boot",
        "//runsc/cgroup",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/specutils",
        "//test/metricclient",
        "@com_github_cenkalti_backoff//:go_default_library",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_kr_pty//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_grpc//:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "serialization_test",
    srcs = ["serialization_test.go"],
    deps = [
        ":container",
        "//runsc/sandbox",
        "@org_golang_google_protobuf//proto:go_default_library",
    ],
)
