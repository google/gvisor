load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sentrycli",
    srcs = ["sentrycli.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//runsc/cli",
        "//runsc/cmd/sentry/sentrycmd",
        "//runsc/cmd/util",
        "//runsc/gvisorbinaries",
    ],
)
