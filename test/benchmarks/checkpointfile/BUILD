load("//test/benchmarks:defs.bzl", "benchmark_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

benchmark_test(
    name = "checkpointfile_test",
    srcs = ["checkpointfile.go"],
    use_for_pgo = False,
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/memutil",
        "//pkg/sentry/checkpoint",
        "//pkg/sentry/fsimpl/host",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/systrap",
        "//pkg/sentry/state/checkpointfiles",
        "//pkg/sentry/vfs",
        "//pkg/state",
        "//pkg/state/statefile",
        "//pkg/test/dockerutil",
        "//pkg/test/testutil",
        "//runsc/boot",
        "//test/benchmarks/harness",
        "@com_github_docker_docker//client:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
