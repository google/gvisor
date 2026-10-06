load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "buildkite",
    srcs = [
        "client.go",
        "stacks.go",
    ],
    importpath = "gvisor.dev/gvisor/tools/buildkite_coordinator/buildkite",
    visibility = ["//tools/buildkite_coordinator:__subpackages__"],
)
