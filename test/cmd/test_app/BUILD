load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "test_app",
    testonly = 1,
    srcs = [
        "fds.go",
        "main.go",
    ],
    pure = True,
    visibility = ["//runsc/container:__pkg__"],
    deps = [
        "//pkg/test/testutil",
        "//pkg/unet",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_kr_pty//:go_default_library",
    ],
)
