load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "forwardcmd",
    srcs = [
        "metric_metadata.go",
        "symbolize.go",
        "syscalls.go",
    ],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/coverage",
        "//pkg/metric",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@org_golang_google_protobuf//encoding/prototext:go_default_library",
    ],
)
