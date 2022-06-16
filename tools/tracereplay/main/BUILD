load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "tracereplay",
    srcs = [
        "main.go",
    ],
    deps = [
        "//runsc/flag",
        "//tools/tracereplay",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
