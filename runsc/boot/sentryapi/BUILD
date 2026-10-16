load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sentryapi",
    srcs = [
        "cgroups.go",
        "controller.go",
        "debug.go",
        "events.go",
        "fs.go",
        "fscheckpoint.go",
        "loader.go",
        "logging.go",
        "metrics.go",
        "mount_hints.go",
        "network.go",
        "pprof.go",
        "restore.go",
        "seccheck.go",
        "sentryapi.go",
        "usage.go",
        "vfs.go",
    ],
    visibility = [
        "//pkg/test:__subpackages__",
        "//runsc:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = [
        "//pkg/fsutil",
        "//pkg/log",
        "//pkg/sentry/fscheckpoint",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/sinks/null",
        "//pkg/sentry/seccheck/sinks/remote",
        "//pkg/state/statefile",
        "//pkg/urpc",
        "//runsc/config",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "sentryapi_test",
    size = "small",
    srcs = ["mount_hints_test.go"],
    embed = [":sentryapi"],
    deps = [
        "//pkg/sentry/fsimpl/erofs",
        "//runsc/config",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
