load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "sentry",
    srcs = [
        "sentry.go",
        "syscall.go",
    ],
    visibility = ["//:sandbox"],
)
