load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "client",
    srcs = [
        "client.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//runsc/config",
        "//runsc/container",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)

go_test(
    name = "client_test",
    size = "small",
    srcs = [
        "client_test.go",
    ],
    embed = [":client"],
    deps = [
        "//runsc/config",
        "//runsc/container",
    ],
)
