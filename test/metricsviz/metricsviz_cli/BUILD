load("//tools:defs.bzl", "go_binary", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "metricsviz_cli",
    srcs = ["metricsviz_cli.go"],
    deps = ["//test/metricsviz"],
)

go_test(
    name = "metricsviz_cli_test",
    srcs = ["metricsviz_cli_test.go"],
    data = [":metricsviz_cli"],
    deps = [
        "//pkg/metric",
        "//pkg/test/testutil",
        "//test/metricsviz",
    ],
)
