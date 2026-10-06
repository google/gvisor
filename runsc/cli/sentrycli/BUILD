load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sentrycli",
    srcs = ["sentrycli.go"],
    importpath = "gvisor.dev/gvisor/runsc/cli/sentrycli",
    visibility = ["//visibility:public"],
    deps = [
        "//runsc/cli",
        "//runsc/cmd/sentry/sentrycmd",
        "//runsc/cmd/util",
        "//runsc/gvisorbinaries",
    ],
)
