load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "trace",
    srcs = [
        "create.go",
        "delete.go",
        "list.go",
        "metadata.go",
        "procfs.go",
        "trace.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "//pkg/sentry/seccheck",
        "//runsc/boot",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/container",
        "//runsc/flag",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

go_test(
    name = "trace_test",
    size = "small",
    srcs = ["create_test.go"],
    library = ":trace",
    deps = [
        "//pkg/sentry/seccheck",
        "//pkg/test/testutil",
        "//runsc/boot",
    ],
)
