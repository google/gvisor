load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

filegroup(
    name = "go_export_sources",
    srcs = glob(
        ["*.go"],
        exclude = ["*_test.go"],
    ),
    visibility = ["//:__pkg__"],
)

go_binary(
    name = "runsc-metric-server",
    srcs = [
        "metricserver_main.go",
    ],
    noasan = True,
    pure = True,
    visibility = [
        "//:sandbox",
    ],
    x_defs = {"gvisor.dev/gvisor/runsc/version.version": "{STABLE_VERSION}"},
    deps = [
        "//pkg/log",
        "//runsc/cmd/metricserver/metricservercmd",
        "//runsc/cmd/util",
        "//runsc/config",
        "//runsc/flag",
        "//runsc/gvisorbinaries",
        "//runsc/metricserver",
        "@com_github_google_subcommands//:go_default_library",
    ],
)
