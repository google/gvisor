load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "autoplatform",
    srcs = [
        "autoplatform.go",
        "platform_list.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/sentry/platform/platformdesc",
        "//runsc/config",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "autoplatform_test",
    size = "small",
    srcs = ["autoplatform_test.go"],
    embed = [":autoplatform"],
    deps = ["//runsc/config"],
)
