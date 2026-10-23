load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "util",
    srcs = [
        "tpu.go",
        "util.go",
    ],
    importpath = "gvisor.dev/gvisor/runsc/cmd/util",
    visibility = [
        "//runsc:__subpackages__",
        "//tools:__subpackages__",
    ],
    deps = [
        "//pkg/abi/tpu",
        "//pkg/log",
        "//runsc/config",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "util_test",
    size = "small",
    srcs = ["tpu_test.go"],
    embed = [":util"],
    deps = ["//pkg/abi/tpu"],
)
