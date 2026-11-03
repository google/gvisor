load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "maincli",
    srcs = [
        "maincli.go",
    ],
    visibility = [
        "//:__pkg__",
        "//runsc:__pkg__",
    ],
    deps = [
        "//runsc/cli",
        "//runsc/cli/maxprocs",
        "//runsc/cmd",
        "//runsc/cmd/alias",
        "//runsc/cmd/profile",
        "//runsc/cmd/trace",
        "//runsc/cmd/util",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

go_test(
    name = "maincli_test",
    srcs = [
        "maincli_test.go",
        "maxprocs_test.go",
    ],
    embed = [":maincli"],
    deps = [
        "//pkg/coverage",
        "//runsc/cmd",
        "//runsc/cmd/sentry/sentrycmd",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
