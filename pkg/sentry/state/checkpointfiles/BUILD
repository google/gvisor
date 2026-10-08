load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "checkpointfiles",
    srcs = ["checkpointfiles.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/state/checkpointfiles",
    visibility = ["//:sandbox"],
)
