load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "procfs",
    srcs = ["dump.go"],
    importpath = "gvisor.dev/gvisor/runsc/boot/procfs",
    visibility = ["//runsc:__subpackages__"],
    deps = [
        "//pkg/hostarch",
        "//pkg/sentry/limits",
    ],
)
