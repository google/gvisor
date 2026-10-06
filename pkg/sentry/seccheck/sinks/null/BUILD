load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "null",
    srcs = ["null.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/seccheck/sinks/null",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/fd",
        "//pkg/sentry/seccheck",
    ],
)
