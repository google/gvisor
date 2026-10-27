load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "setupk8s",
    srcs = ["setupk8s.go"],
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/version",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "setupk8s_test",
    srcs = ["setupk8s_test.go"],
    data = ["//:release"],
    embed = [":setupk8s"],
    deps = [
        "//pkg/test/testutil",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
