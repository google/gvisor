load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "maincli",
    srcs = ["maincli.go"],
    visibility = [
        "//:__pkg__",
        "//runsc:__pkg__",
    ],
    deps = [
        "//runsc/cli",
        "//runsc/cmd",
        "//runsc/cmd/nvproxy",
        "//runsc/cmd/trace",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

go_test(
    name = "maincli_test",
    srcs = ["maincli_test.go"],
    library = ":maincli",
    deps = [
        "//runsc/cmd",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
