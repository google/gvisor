load("@io_bazel_rules_go//go:def.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "test_app",
    testonly = 1,
    srcs = [
        "fds.go",
        "test_app.go",
    ],
    pure = "on",
    visibility = ["//runsc/container:__pkg__"],
    deps = [
        "//pkg/unet",
        "//runsc/testutil",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
