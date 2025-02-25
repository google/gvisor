load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hostsettings",
    srcs = [
        "hostsettings.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sentry/hostmm",
        "//runsc/config",
    ],
)
