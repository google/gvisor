load("//tools:defs.bzl", "go_binary")
load("//tools/embeddedbinary:defs.bzl", "embedded_binary_go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "runsc-metric-server",
    srcs = [
        "metricserver_main.go",
    ],
    features = ["no_default_linker_script"],
    static = True,
    visibility = [
        "//:sandbox",
    ],
    deps = [
        "//pkg/log",
        "//runsc/cmd/metricserver/metricservercmd",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/metricserver",
        "@com_github_google_subcommands//:go_default_library",
    ],
)

embedded_binary_go_library(
    name = "metricserver",
    binary = ":runsc-metric-server",
    visibility = [
        "//runsc:__subpackages__",
    ],
)
