load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "forwardcmd",
    srcs = [
        "forwardcmd.go",
        "metric_metadata.go",
        "statefile.go",
        "symbolize.go",
        "syscalls.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/coverage",
        "//pkg/cpuid",
        "//pkg/metric",
        "//pkg/sentry/pgalloc/metadata",
        "//pkg/state/pretty",
        "//pkg/state/statefile",
        "//runsc/boot/sentryapi",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "forwardcmd_test",
    size = "small",
    srcs = ["statefile_test.go"],
    embed = [":forwardcmd"],
    deps = [
        "//pkg/sentry/pgalloc:pgalloc_metadata_go_proto",
        "//pkg/state",
        "//pkg/state/pretty",
        "//pkg/state/statefile",
        "//pkg/state/wire",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
